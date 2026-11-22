use std::{env, fs, path::Path, process::Command};

fn copy_tree(source: &Path, dest: &Path) {
    fs::create_dir_all(dest).expect("create native build source directory");
    for entry in fs::read_dir(source).expect("read vendored sources") {
        let entry = entry.expect("read source entry");
        let kind = entry.file_type().expect("source file type");
        assert!(!kind.is_symlink(), "vendored symlinks are not permitted");
        let target = dest.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy vendored source");
        }
    }
}

fn run(command: &mut Command) {
    assert!(
        command.status().expect("execute installed CMake").success(),
        "native build failed"
    );
}

fn main() {
    let target = env::var("TARGET").expect("Cargo TARGET");
    assert_eq!(
        env::var("HOST").expect("Cargo HOST"),
        target,
        "cross compilation not yet qualified"
    );
    assert!(
        matches!(
            target.as_str(),
            "x86_64-pc-windows-msvc"
                | "x86_64-unknown-linux-gnu"
                | "x86_64-apple-darwin"
                | "aarch64-apple-darwin"
        ),
        "unsupported native target"
    );
    let out = std::path::PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let source = Path::new("../../vendor/randomx");
    println!("cargo:rerun-if-changed=../../vendor/randomx");
    let copied = out.join("source");
    let build = out.join("native");
    copy_tree(source, &copied);
    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(&copied)
        .arg("-B")
        .arg(&build)
        .args([
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_SHARED_LIBS=OFF",
            "-DARCH=default",
            "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
        ]);
    if target.contains("windows") {
        configure.args(["-G", "Visual Studio 17 2022", "-A", "x64"]);
        let workspace = Path::new("../..").canonicalize().expect("workspace path");
        let workspace = workspace.to_string_lossy();
        let workspace = workspace.trim_start_matches(r"\\?\");
        let map = format!("/pathmap:\"{workspace}\"=/monario");
        configure.arg(format!("-DCMAKE_C_FLAGS={map}"));
        configure.arg(format!("-DCMAKE_CXX_FLAGS={map}"));
    } else {
        let workspace = Path::new("../..").canonicalize().expect("workspace path");
        let map = format!("-ffile-prefix-map=\"{}\"=/monario", workspace.display());
        configure.arg(format!("-DCMAKE_C_FLAGS={map}"));
        configure.arg(format!("-DCMAKE_CXX_FLAGS={map}"));
    }
    run(&mut configure);
    run(Command::new("cmake").arg("--build").arg(&build).args([
        "--config",
        "Release",
        "--target",
        "randomx",
        "--parallel",
        "2",
    ]));
    let libdir = if target.contains("windows") {
        build.join("Release")
    } else {
        build
    };
    // MASM emits CodeView object paths even with GenerateDebugInformation=false.
    // Strip native debug metadata before Rust bundles the archive into an rlib.
    let archive = libdir.join(if target.contains("windows") {
        "randomx.lib"
    } else {
        "librandomx.a"
    });
    let (strip, flag) = if target.contains("windows") {
        let installed =
            std::path::PathBuf::from(env::var_os("ProgramFiles").expect("ProgramFiles"))
                .join("LLVM/bin/llvm-objcopy.exe");
        assert!(
            installed.is_file(),
            "LLVM objcopy is required to strip native build paths"
        );
        (installed, "--strip-debug")
    } else if target.contains("apple") {
        (std::path::PathBuf::from("/usr/bin/strip"), "-S")
    } else {
        (std::path::PathBuf::from("objcopy"), "--strip-debug")
    };
    run(Command::new(strip).arg(flag).arg(&archive));
    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-lib=static=randomx");
    if target.contains("windows") {
        println!("cargo:rustc-link-lib=advapi32");
    }
    if target.contains("linux") {
        println!("cargo:rustc-link-lib=stdc++");
    } else if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    }
}
