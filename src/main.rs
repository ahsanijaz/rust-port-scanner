use clap::Parser;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The target IP address to scan
    #[arg(short, long)]
    target: IpAddr,

    /// The starting port of the scan range
    #[arg(short = 's', long, default_value_t = 1)]
    start_port: u16,

    /// The ending port of the scan range
    #[arg(short = 'e', long, default_value_t = 65535)]
    end_port: u16,

    /// The number of concurrent threads to use for scanning
    #[arg(short = 'j', long, default_value_t = 200)]
    threads: u16,
}

fn main() {
    // Parse the command-line arguments using clap
    let cli = Cli::parse();

    println!(
        "Scanning {} from port {} to {} with {} threads.",
        cli.target, cli.start_port, cli.end_port, cli.threads
    );

    // Create a channel for threads to send back results
    let (tx, rx) = channel::<(u16, String)>();

    // Divide the port range into chunks and assign each to a thread
    for i in (cli.start_port..=cli.end_port).step_by(cli.threads as usize) {
        let tx = tx.clone();
        let target = cli.target;
        let start = i;
        let end = (i + cli.threads - 1).min(cli.end_port);

        // Spawn a thread to scan a chunk of ports
        thread::spawn(move || {
            for port in start..=end {
                let address = format!("{}:{}", target, port);
                if let Ok(mut stream) =
                    TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(1))
                {
                    // If it's a known HTTP port, send a request to grab the banner
                    if port == 80 || port == 443 || port == 8000 || port == 8080 {
                        stream
                            .write_all(b"GET / HTTP/1.0\r\n\r\n")
                            .unwrap_or_default();
                    }

                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap_or_default();
                    let mut buffer = [0; 512];

                    // Send back the port and banner/status
                    if stream.read(&mut buffer).is_ok() {
                        let banner = String::from_utf8_lossy(&buffer)
                            .trim_end_matches('\0')
                            .to_string();
                        tx.send((port, banner)).unwrap_or_default();
                    } else {
                        tx.send((port, "Open (No banner)".to_string()))
                            .unwrap_or_default();
                    }
                }
            }
        });
    }

    // Drop the original transmitter so the receiver knows when all threads are done
    drop(tx);

    // Collect results from the channel
    let mut results = vec![];
    for (port, banner) in rx {
        results.push((port, banner));
    }

    println!();

    // Sort and print the final results
    results.sort_by(|a, b| a.0.cmp(&b.0));
    for (port, banner) in results {
        if !banner.is_empty() && banner != "Open (No banner)" {
            println!("[+] Port {} is open | Banner: {}", port, banner.trim());
        } else {
            println!("[+] Port {} is open", port);
        }
    }
}
