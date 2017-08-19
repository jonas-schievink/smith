extern crate smith;

extern crate log;
extern crate env_logger;
extern crate clap;

use smith::util;
use smith::agent::Agent;
use smith::config::AgentConfig;

use clap::{Arg, App, ArgMatches};
use env_logger::LogBuilder;
use log::LogLevelFilter;
use std::error::Error;
use std::env;

/// Processes command line arguments by overwriting parts of the `AgentConfig` that are specified in
/// `args`.
fn process_args(args: &ArgMatches, conf: &mut AgentConfig) -> Result<(), Box<Error>> {
    if let Some(sock) = args.value_of("bind_address") {
        conf.auth_sock = Some(sock.to_string());
    }

    if args.is_present("force") {
        conf.remove_sock = true;
    }

    Ok(())
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
    let matches = App::new(env!("CARGO_PKG_NAME"))
                      .version(env!("CARGO_PKG_VERSION"))
                      .author(env!("CARGO_PKG_AUTHORS"))
                      .about(env!("CARGO_PKG_DESCRIPTION"))
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
                               .help("Overwrite the socket file if it already exists"))
                      .get_matches();

    init_logger(&matches);

    let mut agent_conf = AgentConfig::default();
    util::unwrap_or_exit(process_args(&matches, &mut agent_conf));

    let mut agent = util::unwrap_or_exit(Agent::new(agent_conf));
    agent.run();
}
