#!/bin/sh
# easy-proxy 安装脚本
# 用法: curl -fsSL https://raw.githubusercontent.com/Hanyang-Li/easy-proxy/main/install.sh | sh
set -eu

REPO="Hanyang-Li/easy-proxy"
BIN="easy-proxy"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

info() {
  printf '\033[1;32m✔\033[0m %s\n' "$1"
}

fail() {
  printf '\033[1;31m✘\033[0m %s\n' "$1" >&2
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "仅支持 macOS"
[ "$(uname -m)" = "arm64" ] || fail "仅支持 Apple Silicon (M 系列) Mac"
target="aarch64-apple-darwin"

if [ -n "${VERSION:-}" ]; then
  tag="$VERSION"
else
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
fi
[ -n "$tag" ] || fail "无法获取最新版本号，可设置 VERSION=v0.2.0 后重试"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

url="https://github.com/$REPO/releases/download/$tag/$BIN-$target.tar.gz"
printf '下载 %s\n' "$url"
curl -fsSL "$url" -o "$tmp/$BIN.tar.gz" || fail "下载失败: $url"
tar -xzf "$tmp/$BIN.tar.gz" -C "$tmp"
chmod +x "$tmp/$BIN"

mkdir -p "$INSTALL_DIR" 2>/dev/null || true
# 先 cp 到同目录临时名再 mv（rename 换新 inode）：直接 cp 原地覆盖正在运行的旧二进制会
# 命中 macOS AMFI 签名缓存（同 inode 内容变了指纹不认），之后每次执行都被 Killed: 9
if [ -w "$INSTALL_DIR" ]; then
  cp "$tmp/$BIN" "$INSTALL_DIR/$BIN.new" && mv -f "$INSTALL_DIR/$BIN.new" "$INSTALL_DIR/$BIN"
else
  sudo cp "$tmp/$BIN" "$INSTALL_DIR/$BIN.new" && sudo mv -f "$INSTALL_DIR/$BIN.new" "$INSTALL_DIR/$BIN"
fi
info "已安装 $BIN $tag 到 $INSTALL_DIR/$BIN"

"$INSTALL_DIR/$BIN" install
info "完成。请编辑 ~/.config/easy-proxy/config.yaml 填入 server 与 username，再 source ~/.zshrc"
