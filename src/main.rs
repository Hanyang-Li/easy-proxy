fn main() {
    if let Err(error) = easy_proxy::run() {
        eprintln!("错误: {error:#}");
        std::process::exit(1);
    }
}
