//! Building this crate needs the `bpf-linker` binary, which cargo cannot be
//! told about as a dependency. Keying a rebuild on its path is the closest
//! approximation: replace the linker and this crate is rebuilt with it.
use which::which;

fn main() {
    let bpf_linker = which("bpf-linker").expect("bpf-linker not found on PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.display());
}
