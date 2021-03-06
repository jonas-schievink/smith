#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate quick_error;
extern crate base64;
extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate libc;
extern crate openssl;

mod agent;
mod prompt;
mod protocol;
mod pubkey;

use agent::Agent;
use clap::{App, Arg, ArgMatches};
use log::LevelFilter;

use std::error::Error;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::{env, fs, io, process};

/// Creates the Unix socket to use for the agent.
///
/// This socket must be publicly known to any application that wishes to use the agent, so we do not
/// generate random file names.
fn create_socket(path: Option<PathBuf>, force: bool) -> io::Result<UnixListener> {
    let path = match path {
        Some(path) => path,
        None => {
            let basedirs = xdg::BaseDirectories::new()?;
            basedirs.place_runtime_file("smith.socket")?
        }
    };

    if force && fs::metadata(&path).is_ok() {
        // Path exists, remove it
        info!("removing existing socket file {}", path.display());
        fs::remove_file(&path)?;
    }

    info!("binding to {}", path.display());
    UnixListener::bind(&path)
}

fn run(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let path = args.value_of("bind_address").map(|s| PathBuf::from(s));
    let listener = create_socket(path, args.is_present("force"))?;

    let mut agent = Agent::new();

    if let Some(mut dir) = dirs::home_dir() {
        dir.push(".ssh");
        agent.preload_user_keys_from_dir(&dir);
    } else {
        warn!("couldn't determine user home dir, no keys will be preloaded");
    }

    agent.run(listener);
}

fn init_logger(args: &ArgMatches) {
    let mut builder = env_logger::Builder::from_default_env();

    let default_level = if args.is_present("debug") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter(None, default_level);

    if let Ok(s) = env::var("RUST_LOG") {
        builder.parse_filters(&s);
    }
    builder.init();
}

fn main() {
    let mut app = app_from_crate!()
        .arg(
            Arg::with_name("bind_address")
                .short("a")
                .help("Bind to the given Unix Domain Socket")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug")
                .short("d")
                .help("Enable debug output"),
        )
        .arg(
            Arg::with_name("force")
                .short("f")
                .long("force")
                .help("Overwrite the socket file if it already exists"),
        );

    if cfg!(debug_assertions) {
        // Add dev options
        // TODO
        app = app.subcommand(
            App::new("dev-auth").about("[developer command] authenticate with a running agent"),
        );
    }

    let matches = app.get_matches();

    init_logger(&matches);

    match run(&matches) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}
