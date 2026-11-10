#![forbid(unsafe_code)]

use applyshield::security::SecurityPolicy;
use std::env;

fn print_help() {
    println!(
        "
====================================
             APPLYSHIELD
      Security-First Job Copilot
====================================

USAGE:
    applyshield <COMMAND>

COMMANDS:
    help       Show available commands
    version    Show application version
    status     Show security status

"
    );
}

fn print_version() {
    println!("ApplyShield v{}", env!("CARGO_PKG_VERSION"));
}

fn print_status() {
    let policy = SecurityPolicy::default();

    println!("\n===== APPLYSHIELD STATUS =====");
    println!("Application: ApplyShield");
    println!(
        "Submission enabled: {}",
        policy.allows_external_submission()
    );
    println!(
        "Explicit approval required: {}",
        policy.requires_explicit_approval()
    );
    println!("Security: Default-deny");
    println!("==============================\n");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let command = args.get(1).map(String::as_str).unwrap_or("help");

    match command {
        "help" => print_help(),
        "version" => print_version(),
        "status" => print_status(),

        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Run 'applyshield help' for available commands.");
            std::process::exit(2);
        }
    }
}
