//! Contains code for generating code to export our environment variables as shell scripts

// FIXME csh support

use std::str::FromStr;
use std::fmt::Display;

/// Enumerates known shells
pub enum Shell {
    /// The classic Bourne shell or compatible shells
    Bourne,
    /// The Friendly Interactive Shell
    Fish,
}

impl FromStr for Shell {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sh" | "bash" | "zsh" => Ok(Shell::Bourne),
            "fish" => Ok(Shell::Fish),
            _ => Err(format!("unknown shell '{}'", s)),
        }
    }
}

impl Shell {
    /// Generate code to export an environment variable
    pub fn export_var<V: Display>(&self, name: &str, value: V) -> String {
        // FIXME: Check if `name` is valid

        match *self {
            Shell::Bourne => format!("export \"{}={}\"", name, value),
            Shell::Fish => format!("set -x \"{}\" \"{}\"", name, value),
        }
    }
}
