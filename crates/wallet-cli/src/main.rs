use monario_wallet_cli::{self as cli, Command};
use std::io::{self, IsTerminal, Write};

fn main() {
    let result = (|| {
        let command = Command::parse(std::env::args_os().skip(1))?;
        if command.needs_password() && io::stdin().is_terminal() {
            return Err(cli::Error::Credentials);
        }
        cli::execute(command, &mut io::stdin().lock(), &mut io::stdout().lock())
    })();
    if let Err(error) = result {
        let _ = writeln!(io::stderr().lock(), "error: {}", error.message());
        std::process::exit(1);
    }
}
