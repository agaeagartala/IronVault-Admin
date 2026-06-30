fn main() {
    // This compiles our visual layout design file during build time
    slint_build::compile("ui/appwindow.slint").unwrap();
}