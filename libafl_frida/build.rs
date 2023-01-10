// build.rs

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    // Force linking against libc++
    #[cfg(unix)]
    println!("cargo:rustc-link-lib=dylib=c++");

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu");
}
