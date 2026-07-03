fn main() {
    #[cfg(target_os = "macos")]
    {
        // Keychain (Touch ID-gated master key) and biometry availability checks.
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }
    tauri_build::build()
}
