// Builds the C matching engine. Warnings are errors, and common hardening
// flags are applied where the compiler supports them.
fn main() {
    println!("cargo:rerun-if-changed=c/matcher.c");
    println!("cargo:rerun-if-changed=c/matcher.h");

    cc::Build::new()
        .file("c/matcher.c")
        .include("c")
        .std("c11")
        .opt_level(2)
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .flag_if_supported("-fstack-protector-strong")
        .flag_if_supported("-D_FORTIFY_SOURCE=2")
        .flag_if_supported("-fno-delete-null-pointer-checks")
        .compile("applyshield_matcher");
}
