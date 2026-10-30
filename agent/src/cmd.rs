use std::process::{Command, Stdio};

/// Führt externe Programme aus; als Trait, damit Tests ohne dpkg/apt auskommen.
pub trait Runner {
    /// Stdout bei Exit-Code 0, sonst `None`.
    fn run(&self, prog: &str, args: &[&str]) -> Option<String>;
}

pub struct System;

impl Runner for System {
    fn run(&self, prog: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(prog)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if out.status.success() {
            String::from_utf8(out.stdout).ok()
        } else {
            None
        }
    }
}
