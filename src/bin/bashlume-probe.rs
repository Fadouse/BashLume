// SPDX-License-Identifier: GPL-2.0-or-later

fn main() {
    if let Err(error) = bashlume::rules::probe::probe_helper_main(std::env::args_os()) {
        eprintln!("bashlume-probe: {error}");
        std::process::exit(126);
    }
}
