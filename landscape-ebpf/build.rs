#![feature(path_file_prefix)]

use libbpf_cargo::SkeletonBuilder;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::{env, fs};

/// Main function of the build script.
fn main() {
    let project_root = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf_rs");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    println!("build target arch is: {}", target_arch);

    println!("cargo:rerun-if-changed=src/bpf/*");

    for entry in fs::read_dir("src/bpf/").expect("Failed to read directory: src/bpf/") {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                eprintln!("Error reading directory entry: {}", e);
                continue;
            }
        };

        if path.is_dir() {
            continue;
        }

        let file_name = path.file_name().and_then(|name| name.to_str());
        let Some(file_name) = file_name else {
            eprintln!("Invalid file name: {:?}", path);
            continue;
        };

        if !file_name.ends_with(".bpf.c") {
            continue;
        }

        let file_stem = file_name.trim_end_matches(".bpf.c");
        let output_file = project_root.join(format!("{}.skel.rs", file_stem));

        println!("Processing input file: {:?}", path);
        println!("Generating output file: {:?}", output_file);

        SkeletonBuilder::new()
            .source(&path)
            .clang_args([
                OsStr::new("-Wall"),
                OsStr::new("-Wno-compare-distinct-pointer-types"),
                OsStr::new("-I"),
                vmlinux::include_path_root().join(&target_arch).as_os_str(),
            ])
            .build_and_generate(&output_file)
            .expect("Failed to build and generate skeleton file");
    }
}
