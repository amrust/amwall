// amwall — interactive install / verify / remove demo.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Walks the full upstream-style WFP flow end-to-end:
//   1. Open the user-mode engine.
//   2. Register a session-scoped provider + sublayer + filter, with
//      conditions matching `cmd.exe → remote port 65530`.
//   3. Print the filter's GUID + runtime id and pause for manual
//      verification via `netsh wfp show filters`.
//   4. Delete the filter explicitly via `Filter::delete`.
//   5. Drop the engine — kernel removes the provider + sublayer.
//
// The Permit action + unreachable-port match means the filter is
// installed in-kernel but cannot fire on real traffic. Run from an
// elevated shell:
//
//     cargo run --example install_demo
//
// Non-Windows hosts: this example does not compile.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, BufRead, Write};
    use std::path::PathBuf;

    use amwall::wfp::condition::FilterCondition;
    use amwall::wfp::filter::{self, FilterAction};
    use amwall::wfp::{provider, sublayer, WfpEngine};
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    let engine = WfpEngine::open()?;
    println!("✓ engine opened");

    let prov = provider::add(&engine, "amwall demo", "install_demo example", false)?;
    println!("✓ provider registered: {:?}", prov.key());

    let sub = sublayer::add(
        &engine,
        "amwall demo sublayer",
        "install_demo example",
        0x4000,
        Some(&prov.key()),
        false,
    )?;
    println!("✓ sublayer registered: {:?}", sub.key());

    let conds = [
        FilterCondition::AppPath(PathBuf::from(r"C:\Windows\System32\cmd.exe")),
        FilterCondition::RemotePort(65530),
    ];
    let f = filter::add(
        &engine,
        "amwall demo filter",
        "permit cmd.exe → :65530",
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &sub.key(),
        Some(&prov.key()),
        &conds,
        FilterAction::Permit,
        false,
        None,
    )?;
    let key = f.key();
    println!(
        "\n✓ filter installed",
    );
    println!(
        "    key:        {{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        key.data1, key.data2, key.data3,
        key.data4[0], key.data4[1], key.data4[2], key.data4[3],
        key.data4[4], key.data4[5], key.data4[6], key.data4[7],
    );
    println!("    runtime id: {}", f.runtime_id());

    println!("\nVerify in another elevated terminal:");
    println!("    cd $env:TEMP; netsh wfp show filters; findstr /i \"amwall\" filters.xml");
    println!("(`netsh wfp show filters` writes filters.xml to cwd; it does NOT print to stdout.)");
    println!("\nPress Enter to delete the filter and exit.");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;

    let report = engine.cleanup_provider(&prov.key())?;
    println!(
        "✓ cleanup_provider: {} filter(s), {} sublayer(s), provider_deleted={}",
        report.filters_deleted, report.sublayers_deleted, report.provider_deleted,
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("install_demo is Windows-only (Windows Filtering Platform).");
    std::process::exit(1);
}
