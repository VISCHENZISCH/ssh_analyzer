use std::fs;
use std::env;
use std::process;

use ssh_analyzer::error::AppError;
use ssh_analyzer::parser::parse_line;
use ssh_analyzer::analyzer::Analyzer;
use ssh_analyzer::report::{print_report, Report};

pub struct Config {
    pub file_path: String,
    pub threshold: u32,
}

impl Config {
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 2 {
            return Err("usage : ssh_analyzer <fichier> [seuil]");
        }

        let file_path = args[1].clone();

        let threshold = if args.len() >= 3 {
            args[2]
                .parse::<u32>()
                .map_err(|_| "le seuil doit être un entier positif")?
        } else {
            5
        };

        Ok(Config {
            file_path,
            threshold,
        })
    }
}

fn run(config: Config) -> Result<(), AppError> {
    let contents = fs::read_to_string(&config.file_path)?;

    let mut analyzer = Analyzer::new();

    for line in contents.lines() {
        analyzer.lines_read += 1;

        match parse_line(line) {
            Ok(event) => analyzer.process(event),
            Err(e) => {
                analyzer.lines_skipped += 1;
                eprintln!("[SKIP] ligne {} : {}", analyzer.lines_read, e);
            }
        }
    }

    println!("\n============= Rapport SSH =============\n");
    print_report(&analyzer);

    println!("\n--- Détails par IP ---\n");
    let mut entries: Vec<&ssh_analyzer::analyzer::IpStats> =
        analyzer.stats.values().collect();
    entries.sort_by(|a, b| b.failed_attempts.cmp(&a.failed_attempts));

    for ip_stats in &entries {
        let prefix = if ip_stats.is_compromised(config.threshold) {
            "[!!] "
        } else if ip_stats.is_suspect(config.threshold) {
            "[!]  "
        } else {
            "     "
        };
        println!("{}{}", prefix, ip_stats.summary());
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Config::build(&args).unwrap_or_else(|err| {
        eprintln!("Erreur de configuration : {}", err);
        process::exit(1);
    });

    if let Err(e) = run(config) {
        eprintln!("Erreur : {}", e);
        process::exit(1);
    }
}
