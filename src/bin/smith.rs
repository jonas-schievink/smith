extern crate smith;

extern crate env_logger;
extern crate clap;

use smith::util;
use smith::agent::Agent;
use smith::config::AgentConfig;
use smith::shells::Shell;

use clap::{Arg, App, ArgMatches};
use std::error::Error;
use std::str::FromStr;

/// Processes command line arguments by overwriting parts of the `AgentConfig` that are specified in
/// `args`.
fn process_args(args: &ArgMatches, conf: &mut AgentConfig) -> Result<(), Box<Error>> {
    if let Some(shell) = args.value_of("shell") {
        conf.shell = Some(try!(Shell::from_str(shell)));
    }

    if let Some(sock) = args.value_of("bind_address") {
        conf.auth_sock = Some(sock.to_string());
    }

    Ok(())
}

fn main() {
    env_logger::init().unwrap();
    let matches = App::new(env!("CARGO_PKG_NAME"))
                      .version(env!("CARGO_PKG_VERSION"))
                      .author(env!("CARGO_PKG_AUTHORS"))
                      .about(env!("CARGO_PKG_DESCRIPTION"))
                      .arg(Arg::with_name("shell")
                               .long("shell")
                               .value_name("SHELL")
                               .help("Set the shell for which to output env vars")
                               .takes_value(true))
                      .arg(Arg::with_name("bind_address")
                               .short("a")
                               .help("Bind to the given Unix Domain Socket")
                               .takes_value(true))
                      .arg(Arg::with_name("debug")
                               .short("d")
                               .help("Enable debug output"))
                      .get_matches();

    let mut agent_conf = AgentConfig::default();
    util::unwrap_or_exit(process_args(&matches, &mut agent_conf));

    let mut agent = Agent::new(agent_conf);
    agent.output_env_vars();
    agent.run();
}
