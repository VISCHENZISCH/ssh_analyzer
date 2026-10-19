use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;

use ssh_analyzer::analyzer::{Analyzer, ThreatStatus};
use ssh_analyzer::error::{AppError, ParseError};
use ssh_analyzer::parser::parse_line;
use ssh_analyzer::report::{ReportOptions, generate_firewall_rules};

#[derive(Parser, Debug)]
#[command(
    name = "ssh_analyzer",
    author = "VISCHENZISCH",
    version,
    about = "Analyseur de logs SSH performant - Détecte les attaques par force brute et les compromissions",
    long_about = None
)]
pub struct Cli {
    /// Chemin vers le fichier de logs auth.log (ou '-' pour lire depuis l'entrée standard)
    #[arg(value_name = "FICHIER")]
    pub file_path: PathBuf,

    /// Seuil de tentatives échouées pour considérer une IP suspecte (défaut : 5)
    #[arg(value_name = "SEUIL", default_value_t = 5)]
    pub threshold: u32,

    /// Activer le mode verbeux (affiche les événements ignorés et détails de parsing)
    #[arg(short, long)]
    pub verbose: bool,

    /// Exporter le rapport complet au format JSON
    #[arg(long)]
    pub json: bool,

    /// Afficher toutes les adresses IP (y compris les connexions normales [OK])
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Limiter l'affichage aux N premières adresses IP
    #[arg(long, value_name = "N")]
    pub top: Option<usize>,

    /// Afficher les règles de pare-feu recommandées (nftables, ufw, iptables)
    #[arg(short, long)]
    pub block_rules: bool,

    /// Enregistrer les règles de pare-feu dans un script shell exécutable
    #[arg(long, value_name = "FICHIER")]
    pub save_rules: Option<PathBuf>,
}

fn open_reader(path: &Path) -> Result<Box<dyn BufRead>, AppError> {
    if path.to_str() == Some("-") {
        let stdin = std::io::stdin();
        return Ok(Box::new(BufReader::new(stdin)));
    }

    let file = File::open(path)?;
    if path.extension().and_then(|ext| ext.to_str()) == Some("gz") {
        let gz = flate2::read::GzDecoder::new(file);
        Ok(Box::new(BufReader::new(gz)))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    let reader = open_reader(&cli.file_path)?;
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

    let report_opts = ReportOptions {
        threshold: cli.threshold,
        show_all: cli.all,
        top_n: cli.top,
    };

    println!("\n============= Rapport SSH =============\n");
    println!("{}", analyzer.summary_with_options(&report_opts));

    if cli.block_rules {
        println!("\n============= Règles de pare-feu recommandées =============\n");
        println!("{}", generate_firewall_rules(&analyzer, cli.threshold));
    }

    if let Some(ref save_path) = cli.save_rules {
        let rules = generate_firewall_rules(&analyzer, cli.threshold);
        let script = format!(
            "#!/usr/bin/env bash\n# Généré automatiquement par ssh_analyzer\nset -euo pipefail\n\n{}\n",
            rules
        );
        std::fs::write(save_path, script)?;
        println!("\n[+] Script pare-feu enregistré avec succès dans : {}", save_path.display());
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
