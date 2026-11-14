<<<<<<< HEAD
mod security; //import another rust module

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
    let policy = security::SecurityPolicy::default();

    println!("\n===== APPLYSHIELD STATUS =====");
    println!("Application: ApplyShield");
    println!("Submission enabled: {}", policy.allow_external_submission);
    println!(
        "Explicit approval required: {}",
        policy.require_explicit_approval
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
=======
#![forbid(unsafe_code)]

use applyshield::cli::{self, Ctx, Io};
use std::env;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Where data lives: `--data-dir`, else `APPLYSHIELD_HOME`, else `~/.applyshield`.
/// The environment is read only to locate files. It never affects security
/// decisions.
fn default_data_dir() -> Option<PathBuf> {
    if let Some(p) = env::var_os("APPLYSHIELD_HOME").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".applyshield"))
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (dir_arg, rest) = match cli::split_global_args(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let Some(data_dir) = dir_arg.or_else(default_data_dir) else {
        eprintln!("error: cannot find a home directory; pass --data-dir <DIR>");
        std::process::exit(2);
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ctx = Ctx {
        data_dir,
        interactive: io::stdin().is_terminal() && io::stdout().is_terminal(),
        now,
    };

    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let mut io = Io {
        stdin: &mut stdin_lock,
        out: &mut stdout,
        err: &mut stderr,
    };
    std::process::exit(cli::run(&rest, &ctx, &mut io));
>>>>>>> c31ce4e (Update in Applysheild)
}
