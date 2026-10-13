// amwall — build script.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// On Windows: compile `assets/amwall.rc` → `.res` and link
// it into the binary. The .rc references the application manifest
// (which opts us into ComCtl32 v6 for visual styles + themed
// controls) plus the app icon. On non-Windows hosts the script is
// a no-op so `cargo doc` / cross-target builds keep working.

fn main() {
    println!("cargo:rerun-if-changed=locales");

    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/amwall.rc");
        println!("cargo:rerun-if-changed=assets/manifest.xml");
        println!("cargo:rerun-if-changed=assets/icons/100.ico");
        // Native UI tests must load the same ComCtl32 v6 assembly as the app.
        // The bin-only form leaves unit tests on the legacy common controls.
        embed_resource::compile_for_everything("assets/amwall.rc", embed_resource::NONE);
    }
}
