fn main() {
    // Compile GResource if it exists
    if std::path::Path::new("data/resources.gresource.xml").exists() {
        glib_build_tools::compile_resources(
            &["data"],
            "data/resources.gresource.xml",
            "openvpn3_indicator.gresource",
        );
    }
}
