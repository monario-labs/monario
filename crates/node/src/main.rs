use monario_node::cli::{self, Command};
use std::{
    io::{self, IsTerminal, Write},
    sync::{Arc, atomic::AtomicBool},
};

fn main() {
    let result = (|| {
        let command = Command::parse(std::env::args_os().skip(1))?;
        if command.needs_password() && io::stdin().is_terminal() {
            return Err(cli::Error::Credentials);
        }
        let stop = Arc::new(AtomicBool::new(false));
        cli::execute(
            command,
            &mut io::stdin().lock(),
            &mut io::stdout().lock(),
            &stop,
        )
    })();
    if let Err(error) = result {
        // Never print arguments, input bytes, paths, SQL diagnostics or key material.
        let _ = writeln!(io::stderr().lock(), "error: {}", error.message());
        std::process::exit(1);
    }
}
