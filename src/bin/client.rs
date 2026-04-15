use std::io::{self, BufRead};

use anyhow::{anyhow, Result};

use signal_playground::client::Client;
use signal_playground::worker_api::{handle_command, Command, CommandResponse};

fn parse_args() -> Result<(String, String, String)> {
    let mut args = std::env::args().skip(1);

    let mut name: Option<String> = None;
    let mut key_repository_url: Option<String> = None;
    let mut relay_url: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => {
                name = args.next();
            }
            "--key-repository-url" => {
                key_repository_url = args.next();
            }
            "--relay-url" => {
                relay_url = args.next();
            }
            _ => {}
        }
    }

    let name = name.ok_or_else(|| anyhow!("Missing --name"))?;
    let key_repository_url =
        key_repository_url.ok_or_else(|| anyhow!("Missing --key-repository-url"))?;
    let relay_url = relay_url.ok_or_else(|| anyhow!("Missing --relay-url"))?;

    Ok((name, key_repository_url, relay_url))
}

fn print_response(response: &CommandResponse) {
    println!("{}", serde_json::to_string(response).unwrap());
}

fn print_response_ok(message: &str) {
    let response = CommandResponse::ok(message);
    print_response(&response);
}

fn print_response_error(message: &str) {
    let response = CommandResponse::error(message);
    print_response(&response);
}

fn main() -> Result<()> {
    let (name, key_repository_url, relay_url) = parse_args()?;

    let mut client = Client::new(&name)?;

    eprintln!(
        "[CLIENT {}] started, KEY_REPOSITORY={}, RELAY={}",
        name, key_repository_url, relay_url
    );

    let stdin = io::stdin();
    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(line) => line,
            Err(err) => {
                print_response_error(&format!("stdin read error: {}", err));
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let command: Command = match serde_json::from_str(&line) {
            Ok(cmd) => cmd,
            Err(err) => {
                print_response_error(&format!("invalid command json: {}", err));
                continue;
            }
        };

        match handle_command(&mut client, &key_repository_url, &relay_url, command) {
            Ok(message) => print_response_ok(&message),
            Err(err) => print_response_error(&err.to_string()),
        }
    }

    Ok(())
}
