fn main() {
    if let Err(error) = easy_proxy::run() {
        eprintln!("{}", easy_proxy::top_error(&format!("{error:#}")));
        std::process::exit(1);
    }
}
