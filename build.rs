fn main() {
    println!("cargo:rerun-if-changed=src/readline_trampoline.c");
    cc::Build::new()
        .file("src/readline_trampoline.c")
        .warnings(true)
        .compile("bashlume-readline-trampoline");
}
