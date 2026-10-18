use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use ssh_analyzer::analyzer::{Analyzer, ThreatStatus};
use ssh_analyzer::error::{AppError, ParseError};
use ssh_analyzer::parser::parse_line;
use ssh_analyzer::report::{Report, generate_firewall_rules};

#[derive(Parser, Debug)]
#[command(
    name = "ssh_analyzer",
    author = "VISCHENZISCH",
    version,
    about = "Analyseur de logs SSH performant - Détecte les attaques par force brute et les compromissions",
    long_about = None
)]
pub struct Cli {
    /// Chemin vers le fichier de logs auth.log
    #[arg(value_name = "FICHIER")]
    pub file_path: PathBuf,

    /// Seuil de tentatives échouées pour considérer une IP suspecte (défaut : 5)
    #[arg(value_name = "SEUIL", default_value_t = 5)]
    pub threshold: u32,

    /// Activer le mode verbeux (affiche les événements ignorés et détails de parsing)
    #[arg(short, long)]
    pub verbose: bool,

    /// Exporter le rapport au format JSON
    #[arg(long)]
    pub json: bool,

    /// Générer des règles de pare-feu (ufw, iptables) pour bloquer les IP suspectes
    #[arg(short, long)]
    pub block_rules: bool,
}

fn run(cli: Cli) -> Result<(), AppError> {
    let file = File::open(&cli.file_path)?;
    let reader = BufReader::new(file);

    let mut analyzer = Analyzer::new();

    for line_result in reader.lines() {
        let line = line_result?;
        analyzer.lines_read += 1;

        match parse_line(&line) {
            Ok(event) => analyzer.process(event),
            Err(ParseError::NotSshEvent) => {
                analyzer.non_ssh_lines += 1;
                if cli.verbose {
                    eprintln!("[VERBOSE] ligne {} : non-SSH event", analyzer.lines_read);
                }
            }
            Err(ParseError::EmptyLine) => {
                if cli.verbose {
                    eprintln!("[VERBOSE] ligne {} : ligne vide", analyzer.lines_read);
                }
            }
            Err(e) => {
                analyzer.lines_skipped += 1;
                if cli.verbose {
                    eprintln!("[SKIP] ligne {} : {}", analyzer.lines_read, e);
                }
            }
        }
    }

    if cli.json {
        let json_output = serde_json::to_string_pretty(&analyzer)?;
        println!("{}", json_output);
        return Ok(());
    }

    println!("\n============= Rapport SSH =============\n");
    println!("{}", analyzer.summary(cli.threshold));

    if cli.block_rules {
        println!("\n============= Règles de pare-feu recommandées =============\n");
        println!("{}", generate_firewall_rules(&analyzer, cli.threshold));
    }

    let has_compromise = analyzer
        .stats
        .values()
        .any(|s| s.status(cli.threshold) == ThreatStatus::Compromised);

    if has_compromise {
        process::exit(2);
    }

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Erreur : {}", e);
        process::exit(1);
    }
}
