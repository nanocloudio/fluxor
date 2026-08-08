fn main() {
    // The triple the tools are compiled FOR is the host they run on;
    // `module_test` pins generated harness crates to it so the repo's
    // bare-metal `.cargo/config` default target can't leak into host
    // test builds.
    println!(
        "cargo:rustc-env=FLUXOR_HOST_TRIPLE={}",
        std::env::var("TARGET").expect("cargo always sets TARGET for build scripts")
    );
}
