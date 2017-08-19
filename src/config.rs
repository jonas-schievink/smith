//! Contains config file parsing routines and provides the `AgentConfig` struct, which defines the
//! behaviour of the agent.

/// Configures the agent's behaviour
#[derive(Default)]
pub struct AgentConfig {
    /// The socket to listen on can be configured by setting the `SSH_AUTH_SOCK` environment
    /// variable before starting the agent.
    pub auth_sock: Option<String>,
    /// If `true`, we'll try to delete an existing socket file instead of exiting with an error.
    pub remove_sock: bool,
}
