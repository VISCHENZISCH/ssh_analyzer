use std::fmt;
use std::io;

#[derive(Debug)]
pub enum ParseError {
    EmptyLine,
    UnknownEvent,
    InvalidIp(String),
    InvalidUser(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::EmptyLine => write!(f, "empty line"),
            ParseError::UnknownEvent => write!(f, "unrecognized SSH event"),
            ParseError::InvalidIp(ip) => write!(f, "invalid IP address: {}", ip),
            ParseError::InvalidUser(user) => write!(f, "invalid user: {}", user),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug)]
pub enum AppError {
    Io(io::Error),
    Parse(ParseError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "I/O error: {}", e),
            AppError::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for AppError {
   
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io(e) => Some(e),
            AppError::Parse(e) => Some(e),
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
