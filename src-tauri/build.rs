use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::Path,
    process::Command,
};

const BUILD_INPUTS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "ui",
    "src-tauri/build.rs",
    "src-tauri/Cargo.toml",
    "src-tauri/Cargo.lock",
    "src-tauri/tauri.conf.json",
    "src-tauri/capabilities",
    "src-tauri/icons",
    "src-tauri/src",
];

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn hash_input(root: &Path, relative: &Path, hash: &mut DefaultHasher) {
    relative.hash(hash);
    let path = root.join(relative);
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(&path)
            .unwrap_or_else(|e| panic!("Cannot read build input {}: {e}", path.display()))
            .map(|entry| entry.expect("Cannot read build input entry").file_name())
            .collect();
        entries.sort();
        for entry in entries {
            hash_input(root, &relative.join(entry), hash);
        }
    } else {
        fs::read(&path)
            .unwrap_or_else(|e| panic!("Cannot read build input {}: {e}", path.display()))
            .hash(hash);
    }
}

fn build_id(root: &Path) -> String {
    let mut hash = DefaultHasher::new();
    for input in BUILD_INPUTS {
        // Watching directories also catches newly added or removed source files.
        println!("cargo:rerun-if-changed={}", root.join(input).display());
        hash_input(root, Path::new(input), &mut hash);
    }
    // Git worktrees keep HEAD and shared refs in different directories.
    for input in ["HEAD", "refs", "packed-refs"] {
        if let Some(path) = git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-path", input],
        ) {
            if Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
    let revision =
        git(root, &["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "source".into());
    // The fingerprint includes uncommitted contents, not just a dirty flag.
    format!("{revision}-{:016x}", hash.finish())
}

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    let root = Path::new(&manifest).parent().expect("Project root");
    println!("cargo:rustc-env=PHOTOVAULT_BUILD_ID={}", build_id(root));
    #[cfg(target_os = "macos")]
    {
        // Keychain (Touch ID-gated master key) and biometry availability checks.
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }
    tauri_build::build()
}
