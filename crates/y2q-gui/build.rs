fn main() {
    // y2q-gui links y2q-mount-windows's WinFsp bindings in-process on
    // Windows, so it needs the same delay-load linker setup y2q-mount-windows
    // itself needs (see that crate's build.rs). No-op on non-Windows.
    #[cfg(windows)]
    winfsp_wrs_build::build();
}
