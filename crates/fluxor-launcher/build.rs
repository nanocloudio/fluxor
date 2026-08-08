fn main() {
    println!(
        "cargo:rustc-env=FLUXOR_HOST_TRIPLE={}",
        std::env::var("TARGET").expect("cargo sets TARGET for build scripts")
    );
}
