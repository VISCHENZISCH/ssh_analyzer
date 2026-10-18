use std::fmt;
use std::io;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    EmptyLine,
    NotSshEvent,
    UnknownSshEvent,
    InvalidIp(String),
    InvalidUser(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyLine => write!(f, "ligne vide"),
            ParseError::NotSshEvent => write!(f, "événement non-SSH (ignoré)"),
            ParseError::UnknownSshEvent => write!(f, "événement SSH non reconnu"),
            ParseError::InvalidIp(ip) => write!(f, "adresse IP invalide : {}", ip),
            ParseError::InvalidUser(user) => write!(f, "utilisateur invalide : {}", user),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug)]
pub enum AppError {
    Io(io::Error),
    Parse(ParseError),
    Json(serde_json::Error),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "Erreur E/S : {}", e),
            AppError::Parse(e) => write!(f, "Erreur de parsing : {}", e),
            AppError::Json(e) => write!(f, "Erreur JSON : {}", e),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io(e) => Some(e),
            AppError::Parse(e) => Some(e),
            AppError::Json(e) => Some(e),
        }
    }
}

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<ParseError> for AppError {
    fn from(e: ParseError) -> Self {
        AppError::Parse(e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Json(e)
    }
}
