#!/bin/sh
# easy-proxy 安装脚本
#
#   curl -fsSL https://raw.githubusercontent.com/Hanyang-Li/easy-proxy/main/install.sh | sh
#
# 环境变量：
#   VERSION=v1.0.0        安装指定版本（默认最新 release）
#   INSTALL_DIR=/path     安装目录（默认 ~/.local/bin，在 $HOME 下、无需 sudo）
#   NO_MODIFY_PATH=1      跳过修改 shell rc，仅打印手动 PATH / FPATH 提示
set -eu

REPO="Hanyang-Li/easy-proxy"
BIN="easy-proxy"
TARGET="aarch64-apple-darwin"
ASSET="$BIN-$TARGET.tar.gz"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
ZSH_FUNCTIONS_DIR="$HOME/.local/share/zsh/site-functions"
CACHE_DIR="$HOME/.cache/easy-proxy"

info() {
  printf '\033[1;32m✔\033[0m %s\n' "$1"
}

fail() {
  printf '\033[1;31m✘\033[0m %s\n' "$1" >&2
  exit 1
}

# 打印手动 PATH 提示（NO_MODIFY_PATH 或未知 shell 时的回退）。
path_hint() {
  printf '提示：%s 不在 PATH 中，可手动添加：\n' "$INSTALL_DIR"
  printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
  printf '或直接运行：%s/%s\n' "$INSTALL_DIR" "$BIN"
}

# 把 $INSTALL_DIR 幂等地写入用户 shell rc 的 PATH。
# 遵循 NO_MODIFY_PATH；未知 shell 回退到 path_hint。
ensure_on_path() {
  if [ -n "${NO_MODIFY_PATH:-}" ]; then
    path_hint
    return
  fi

  marker="# added by easy-proxy installer (PATH)"
  case "$(basename "${SHELL:-}")" in
    zsh)  rc="$HOME/.zshrc";                   line="export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
    bash) rc="$HOME/.bash_profile";            line="export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
    fish) rc="$HOME/.config/fish/config.fish"; line="fish_add_path ${INSTALL_DIR}" ;;
    *)    path_hint; return ;;
  esac

  if [ -f "$rc" ] && grep -qF "$marker" "$rc" 2>/dev/null; then
    info "PATH 已配置（$rc）"
    return
  fi

  mkdir -p "$(dirname "$rc")" 2>/dev/null || true
  if ! { printf '\n%s\n%s\n' "$marker" "$line" >> "$rc"; } 2>/dev/null; then
    path_hint
    return
  fi

  info "已将 ${INSTALL_DIR} 加入 PATH（$rc）"
}

# 打印手动 fpath 提示（NO_MODIFY_PATH 或写入失败时的回退）。
fpath_hint() {
  printf '提示：%s 不在 zsh fpath 中，可手动添加：\n' "$ZSH_FUNCTIONS_DIR"
  printf '  fpath=("%s" $fpath) && autoload -Uz compinit && compinit\n' "$ZSH_FUNCTIONS_DIR"
}

# $1 是否已在交互式 zsh 的 fpath 中。
#
# 安装脚本以 sh 运行，zsh 不导出 $FPATH，无法从环境读取（这里恒为空）。
# 改为直接问 zsh 本身：`zsh -ic` 会 source ~/.zshenv 与 ~/.zshrc（fpath 在此配置），
# 用 shell 内重定向把 $fpath 写到 ~/.cache/easy-proxy 下的临时文件，
# 让 rc banner / instant-prompt 的输出落到被丢弃的 stdout，不污染结果。
# zsh 不可用时回退到 grep ~/.zshrc。
fpath_contains() {
  dir="$1"
  mkdir -p "$CACHE_DIR" 2>/dev/null || true
  tmpf="$(mktemp "$CACHE_DIR/fpath.XXXXXX" 2>/dev/null)" || tmpf=""
  if [ -n "$tmpf" ]; then
    zsh -ic "print -rl -- \$fpath > '$tmpf'" >/dev/null 2>&1 || true
    if [ -s "$tmpf" ]; then
      if grep -qxF "$dir" "$tmpf"; then
        rm -f "$tmpf"
        return 0
      fi
      rm -f "$tmpf"
      return 1
    fi
    rm -f "$tmpf"
  fi
  # zsh 不可用或无输出 → 回退到 grep ~/.zshrc
  if grep -qF "$dir" "$HOME/.zshrc" 2>/dev/null; then
    return 0
  fi
  return 1
}

# 把 $ZSH_FUNCTIONS_DIR 幂等地写入 ~/.zshrc 的 fpath（仅 zsh 调用）。
# 目录已在交互式 fpath 上（无论谁加的）就跳过。遵循 NO_MODIFY_PATH。
ensure_on_fpath() {
  if [ -n "${NO_MODIFY_PATH:-}" ]; then
    fpath_hint
    return
  fi

  rc="$HOME/.zshrc"

  if fpath_contains "$ZSH_FUNCTIONS_DIR"; then
    info "fpath 已包含 ${ZSH_FUNCTIONS_DIR}"
    return
  fi

  marker="# added by easy-proxy installer (FPATH)"
  if ! { printf '\n%s\nfpath=("%s" $fpath)\nautoload -Uz compinit && compinit\n' \
    "$marker" "$ZSH_FUNCTIONS_DIR" >> "$rc"; } 2>/dev/null; then
    fpath_hint
    return
  fi

  info "已将 ${ZSH_FUNCTIONS_DIR} 加入 fpath（$rc）"
}

# --- 环境检查 ---
[ "$(uname -s)" = "Darwin" ] || fail "仅支持 macOS"
[ "$(uname -m)" = "arm64" ] || fail "仅支持 Apple Silicon (M 系列) Mac"
command -v curl >/dev/null 2>&1 || fail "需要 curl"
command -v shasum >/dev/null 2>&1 || fail "需要 shasum"

# --- 解析版本与下载地址 ---
# 用 releases/latest 的网页重定向取 tag，不走 api.github.com——
# 匿名 API 每 IP 每小时仅 60 次，公司出口 NAT 下极易被打光（403）
if [ -n "${VERSION:-}" ]; then
  tag="$VERSION"
else
  tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" |
    sed 's|.*/tag/||')
fi
[ -n "$tag" ] || fail "无法获取最新版本号，可设置 VERSION=v2.0.0 后重试"

base="https://github.com/$REPO/releases/download/$tag"

# --- 下载到临时目录，退出时清理 ---
tmp=$(mktemp -d)
SUDO=""
STAGE=""
cleanup() {
  rm -rf "$tmp"
  [ -n "$STAGE" ] && $SUDO rm -f "$STAGE" 2>/dev/null
  return 0
}
trap cleanup EXIT

printf '下载 %s\n' "$base/$ASSET"
curl -fsSL --proto '=https' "$base/$ASSET" -o "$tmp/$ASSET" || fail "下载失败: $base/$ASSET"
curl -fsSL --proto '=https' "$base/$ASSET.sha256" -o "$tmp/$ASSET.sha256" || fail "下载失败: $base/$ASSET.sha256"

# --- 校验和 ---
printf '验证校验和\n'
( cd "$tmp" && shasum -a 256 -c "$ASSET.sha256" >/dev/null ) || fail "校验和验证失败"

# --- 解压 ---
tar -xzf "$tmp/$ASSET" -C "$tmp" || fail "解压失败"
[ -f "$tmp/$BIN" ] || fail "压缩包中缺少 $BIN"

# --- 判断是否需要提权 ---
# 默认目标 ~/.local/bin 在 $HOME 下、用户可写，无需 sudo；
# 仅当覆盖到不可写目录（如 INSTALL_DIR=/usr/local/bin）时才回退 sudo。
mkdir -p "$INSTALL_DIR" 2>/dev/null || true
if [ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ]; then
  SUDO=""
else
  printf '安装到 %s 需要管理员权限\n' "$INSTALL_DIR"
  SUDO="sudo"
  $SUDO mkdir -p "$INSTALL_DIR"
fi

# --- 同目录原子 rename 安装 ---
# 先在 $INSTALL_DIR 内暂存二进制，再 mv 覆盖，使最终 mv 始终是同文件系统原子 rename。
# rename(2) 只替换目录项、不打开或截断目标：既能替换正在运行的二进制而不触发 ETXTBSY，
# 也让新内容落在新 inode 上——原地 cp 覆盖会命中 macOS AMFI 签名缓存（同 inode 内容变了
# 指纹不认），之后每次执行都被 Killed: 9。跨文件系统的 mv 会退化成 copy 并截断目标。
STAGE="$INSTALL_DIR/.$BIN.tmp.$$"
$SUDO cp "$tmp/$BIN" "$STAGE" || fail "在 $INSTALL_DIR 暂存二进制失败"
$SUDO chmod 0755 "$STAGE"
$SUDO mv "$STAGE" "$INSTALL_DIR/$BIN" || fail "安装二进制到 $INSTALL_DIR 失败"
STAGE=""

info "已安装 $BIN $tag 到 $INSTALL_DIR/$BIN"

# --- 确保二进制在 PATH 上 ---
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) : ;;
  *) ensure_on_path ;;
esac

# --- 确保补全目录在 zsh fpath 上（仅 zsh）---
if [ "$(basename "${SHELL:-}")" = "zsh" ]; then
  ensure_on_fpath
fi

# --- 写默认配置、释放 zju-connect、生成补全、更新 ~/.zshrc 托管块 ---
"$INSTALL_DIR/$BIN" install

info "完成。请编辑 ~/.config/easy-proxy/config.yaml 填入 server 与 username，再 source ~/.zshrc"
