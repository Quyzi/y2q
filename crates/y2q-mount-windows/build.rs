fn main() {
    // Configures delay-loading of the WinFsp DLL (it isn't on the default DLL
    // search path — its install location is only known at runtime via the
    // registry, see `winfsp_wrs::init`). No-op on non-Windows.
    #[cfg(windows)]
    winfsp_wrs_build::build();
}
