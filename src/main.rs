extern crate smith;

#[macro_use] extern crate clap;
extern crate log;
extern crate env_logger;

use smith::agent::Agent;
use smith::config::AgentConfig;

use clap::{Arg, App, ArgMatches};
use env_logger::LogBuilder;
use log::LogLevelFilter;

use std::error::Error;
use std::{env, process};

fn run(args: &ArgMatches) -> Result<(), Box<Error>> {
    let mut conf = AgentConfig::default();

    if let Some(sock) = args.value_of("bind_address") {
        conf.auth_sock = Some(sock.to_string());
    }

    if args.is_present("force") {
        conf.remove_sock = true;
    }

    let mut agent = Agent::new(conf)?;
    agent.run();
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
