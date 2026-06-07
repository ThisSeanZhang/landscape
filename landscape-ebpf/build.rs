use libbpf_cargo::SkeletonBuilder;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn emit_rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());

    if !path.is_dir() {
        return;
    }

    for entry in fs::read_dir(path).expect("Failed to read bpf source directory") {
        let path = entry.expect("Failed to read bpf source entry").path();
        emit_rerun_if_changed(&path);
    }
}

fn build_bpf_in_dir(dir: &Path, project_root: &Path, clang_args: &[&OsStr]) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| {
        panic!("Failed to read directory: {}: {}", dir.display(), e);
    }) {
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

        println!("Processing input file: {:?}", path);
        println!("Generating output skeleton file: {:?}", output_skel_file);

        SkeletonBuilder::new()
            .source(&path)
            .clang_args(clang_args)
            .build_and_generate(&output_skel_file)
            .expect("Failed to build, save object, and generate skeleton file");
    }
}

fn build_test_bpf(base_dir: &Path, project_root: &Path, clang_args: &[&OsStr]) {
    let test_dir = base_dir.join("test");
    if !test_dir.is_dir() {
        return;
    }
    for entry in fs::read_dir(&test_dir).unwrap_or_else(|e| {
        panic!("Failed to read directory: {}: {}", test_dir.display(), e);
    }) {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                eprintln!("Error reading test directory entry: {}", e);
                continue;
            }
        };
        if path.is_dir() {
            build_bpf_in_dir(&path, project_root, clang_args);
        }
    }
}

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

    emit_rerun_if_changed(Path::new("src/bpf"));

    let vmlinux_path = vmlinux::include_path_root().join(&target_arch);
    let mut clang_args: Vec<&OsStr> = vec![
        OsStr::new("-Wall"),
        OsStr::new("-Wno-compare-distinct-pointer-types"),
        OsStr::new("-I"),
        vmlinux_path.as_os_str(),
        OsStr::new("-I"),
        OsStr::new("src/bpf"),
        OsStr::new("-mcpu=v2"),
    ];

    if target_arch.contains("riscv") {
        clang_args.push(OsStr::new("-DLAND_ARCH_RISCV"));
    }

    build_bpf_in_dir(Path::new("src/bpf/"), &project_root, &clang_args);

    build_bpf_in_dir(Path::new("src/bpf/tc_chain/"), &project_root, &clang_args);

    if env::var("PROFILE").map_or(true, |p| p != "release") {
        build_test_bpf(Path::new("src/bpf"), &project_root, &clang_args);
    }
}
