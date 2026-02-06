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

    let vmlinux_path = vmlinux::include_path_root().join(&target_arch);
    let mut clang_args = vec![
        OsStr::new("-Wall"),
        OsStr::new("-Wno-compare-distinct-pointer-types"),
        OsStr::new("-I"),
        vmlinux_path.as_os_str(),
        OsStr::new("-mcpu=v2"),
    ];

    if target_arch.contains("riscv") {
        clang_args.push(OsStr::new("-DLAND_ARCH_RISCV"));
    }

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
        let output_skel_file = project_root.join(format!("{}.skel.rs", file_stem));
        // let output_bpf_obj_file = project_root.join(format!("{}.o", file_stem));

        println!("Processing input file: {:?}", path);
        println!("Generating output skeleton file: {:?}", output_skel_file);
        // println!("Saving BPF object file to: {:?}", output_bpf_obj_file);

        SkeletonBuilder::new()
            // .obj(output_bpf_obj_file)
            .source(&path)
            .clang_args(&clang_args)
            .build_and_generate(&output_skel_file)
            .expect("Failed to build, save object, and generate skeleton file");
    }
}
