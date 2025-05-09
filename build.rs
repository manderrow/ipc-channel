use std::env::{var, var_os};
use std::path::PathBuf;

fn main() {
    let root_dir = PathBuf::from(var_os("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo::rerun-if-env-changed=CARGO_MANIFEST_DIR");
    println!("cargo::rerun-if-changed={:?}", root_dir.join("lib-linux"));

    let target = var("TARGET").unwrap();
    println!("cargo::rerun-if-env-changed=TARGET");
    let (arch, rem) = target.split_once('-').unwrap();
    let (_device, rem) = rem.split_once('-').unwrap();
    let (os, abi) = match rem.split_once('-') {
        Some((os, abi)) => (os, Some(abi)),
        None => (rem, None),
    };
    let debug = var("DEBUG").unwrap().parse().expect("Invalid debug value");
    println!("cargo::rerun-if-env-changed=DEBUG");

    if os != "windows" && os != "linux" {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let mut cache_dir = out_dir.clone();
    cache_dir.push_str("/zig-cache");
    let mut prefix = out_dir;
    prefix.push_str("/zig-out");

    let status = std::process::Command::new("zig")
        .args([
            "build",
            "--cache-dir",
            &cache_dir,
            "-p",
            &prefix,
            &format!("-Doptimize={}", if debug { "Debug" } else { "ReleaseSafe" }),
            &format!(
                "-Dtarget={arch}-{}{}{}",
                match os {
                    "darwin" => "macos",
                    _ => os,
                },
                match abi {
                    Some(_) => "-",
                    None => "",
                },
                match os {
                    "windows" => "gnu",
                    _ => abi.unwrap_or(""),
                }
            ),
        ])
        .current_dir(root_dir.join("lib-linux"))
        .status()
        .unwrap();
    if !status.success() {
        panic!("{status}");
    }

    if os == "windows" {
        std::fs::copy(
            format!("{prefix}/lib/linux.lib"),
            format!("{prefix}/lib/liblinux.a"),
        )
        .unwrap();
    }

    println!("cargo::rustc-link-search={prefix}/lib");
}
