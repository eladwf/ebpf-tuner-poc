// build.rs
use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=bpf/tuner.bpf.c");
    println!("cargo:rerun-if-changed=bpf/sockops.bpf.c");
    println!("cargo:rerun-if-changed=bpf/common.h");
    println!("cargo:rerun-if-changed=bpf/prefetch.bpf.c");
    println!("cargo:rerun-if-changed=bpf/vmlinux.h");

    let clang_args = ["-Ibpf"];

    SkeletonBuilder::new()
        .source("bpf/tuner.bpf.c")
        .clang_args(&clang_args)
        .build_and_generate(out.join("tuner.skel.rs"))
        .expect("skeleton generation for tuner failed");

    SkeletonBuilder::new()
        .source("bpf/sockops.bpf.c")
        .clang_args(&clang_args)
        .build_and_generate(out.join("sockops.skel.rs"))
        .expect("skeleton generation for sockops failed");

    SkeletonBuilder::new()
        .source("bpf/prefetch.bpf.c")
        .clang_args(&clang_args)
        .build_and_generate(out.join("prefetch.skel.rs"))
        .expect("skeleton generation for prefetch failed");

}