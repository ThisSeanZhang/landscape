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

    let bpf_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src").join("bpf");
    let mut clang_args = vec![
        OsStr::new("-Wall"),
        OsStr::new("-Wno-compare-distinct-pointer-types"),
        OsStr::new("-I"),
        Box::leak(bpf_dir.into_os_string().into_boxed_os_str()), // Always include local headers
        OsStr::new("-mcpu=v2"),
    ];

    if env::var("LANDSCAPE_NO_CORE").is_err() {
        println!("Building with CO-RE support");
        let vmlinux_path = vmlinux::include_path_root().join(&target_arch);
        clang_args.push(OsStr::new("-I"));
        // We need to keep the OsString alive if we want to use its reference.
        // For a build script, leaking is fine or we can just use Box::leak.
        let path_str = vmlinux_path.into_os_string();
        clang_args.push(Box::leak(path_str.into_boxed_os_str()));
    } else {
        println!("Building WITHOUT CO-RE support (native compilation)");
        clang_args.push(OsStr::new("-DLANDSCAPE_NO_CORE"));
        // In native build, we rely on system headers and don't include BTF vmlinux.h
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

        // if env::var("LANDSCAPE_NO_CORE").is_ok() {
        //      if file_name == "neigh_update.bpf.c" {
        //          println!("Skipping neigh_update.bpf.c in native build (requires kernel internal structs)");
        //          continue;
        //      }
        // }

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
