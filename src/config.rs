//! Contains config file parsing routines and provides the `AgentConfig` struct, which defines the
//! behaviour of the agent.

use shells::Shell;

/// Configures the agent's behaviour
#[derive(Default)]
pub struct AgentConfig {
    /// The user's shell. Set to `Some` when we want to generate a shell script that sets the right
    /// env vars.
    pub shell: Option<Shell>,
    /// The socket to listen on can be configured by setting the `SSH_AUTH_SOCK` environment
    /// variable before starting the agent.
    pub auth_sock: Option<String>,
    /// If `true`, we'll try to delete an existing socket file instead of exiting with an error.
    pub remove_sock: bool,
}
