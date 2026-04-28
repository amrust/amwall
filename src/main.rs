// simplewall-rs — a Rust port of simplewall (https://github.com/henrypp/simplewall)
// Copyright (C) 2026  simplewall-rs contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version. See LICENSE.

#[cfg(windows)]
mod wfp;

#[cfg(windows)]
fn main() -> Result<(), wfp::WfpError> {
    println!("simplewall-rs (pre-alpha) — see README.md");
    let engine = wfp::WfpEngine::open()?;
    println!("WFP engine handle acquired: {:?}", engine.raw());
    let key = engine.session_key();
    println!(
        "session-key GUID: {{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        key.data1, key.data2, key.data3,
        key.data4[0], key.data4[1], key.data4[2], key.data4[3],
        key.data4[4], key.data4[5], key.data4[6], key.data4[7],
    );
    // engine drops here — FwpmEngineClose0 runs
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("simplewall-rs is Windows-only (Windows Filtering Platform).");
    std::process::exit(1);
}
