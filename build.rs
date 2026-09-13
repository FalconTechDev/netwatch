//! Compiles the in-kernel program and hands the object to the binary that
//! loads it, so the two can never be out of step with each other.
//!
//! Only on Linux, and only when the host is Linux: there is nothing to build
//! otherwise, and on Windows the tools this needs do not exist. `cfg` here is
//! the *host*, because a build script is compiled for the machine running it.

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context as _, anyhow};
    use aya_build::Toolchain;

    // The eBPF crate is built by a pinned nightly rather than whatever
    // `nightly` happens to be today. The linker that turns its output into
    // kernel bytecode carries its own copy of LLVM, and if the compiler's LLVM
    // is newer than the linker's, the bitcode it emits cannot be read and the
    // build fails with "Invalid record" — a message that says nothing about
    // versions. Pinning is what keeps the two in step.
    const TOOLCHAIN: &str = "nightly-2026-04-15";

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("could not read cargo metadata")?;

    let ebpf = packages
        .into_iter()
        .find(|p| p.name.as_str() == "netwatch-ebpf")
        .ok_or_else(|| anyhow!("the netwatch-ebpf package is not in this workspace"))?;

    let root_dir = ebpf
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("netwatch-ebpf has no directory"))?
        .as_str();

    aya_build::build_ebpf(
        [aya_build::Package {
            name: ebpf.name.as_str(),
            root_dir,
            ..Default::default()
        }],
        Toolchain::Custom(TOOLCHAIN),
    )
}

#[cfg(not(target_os = "linux"))]
fn main() {}
