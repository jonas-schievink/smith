extern crate smith;

#[macro_use] extern crate clap;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate unix_socket;
extern crate xdg;

use smith::agent::Agent;

use clap::{Arg, App, ArgMatches};
use env_logger::LogBuilder;
use log::LogLevelFilter;
use unix_socket::UnixListener;

use std::error::Error;
use std::{env, process, io, fs};
use std::path::PathBuf;

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

fn run(args: &ArgMatches) -> Result<(), Box<Error>> {
    let path = args.value_of("bind_address").map(|s| PathBuf::from(s));
    let listener = create_socket(path, args.is_present("force"))?;

    let mut agent = Agent::new();
    agent.run(listener);
}

fn init_logger(args: &ArgMatches) {
    let mut builder = LogBuilder::new();
    builder.format(|record| {
        format!("[{}] {}: {}", record.level(), record.location().module_path(), record.args())
    });

    let default_level = if args.is_present("debug") {
        LogLevelFilter::Debug
    } else {
        LogLevelFilter::Info
    };
    builder.filter(None, default_level);

    if let Ok(s) = env::var("RUST_LOG") {
        builder.parse(&s);
    }
    builder.init().unwrap();
}

fn main() {
    let mut app = app_from_crate!()
        .arg(Arg::with_name("bind_address")
            .short("a")
            .help("Bind to the given Unix Domain Socket")
            .takes_value(true))
        .arg(Arg::with_name("debug")
            .short("d")
            .help("Enable debug output"))
        .arg(Arg::with_name("force")
            .short("f")
            .long("force")
            .help("Overwrite the socket file if it already exists"));

    if cfg!(debug_assertions) {
        // Add dev options
        // TODO
        app = app.subcommand(App::new("dev-auth")
            .help("[developer command] authenticate with a running agent"));
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
