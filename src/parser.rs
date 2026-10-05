use crate::error::ParseError;

#[derive(Debug)]
pub enum SshEvent {
    FailedAuth {
        user: String,
        ip: String,
        invalid_user: bool,
    },
    SuccessAuth {
        user: String,
        ip: String,
    },
    Other,
}

pub fn extract_ip<'a>(line: &'a str) -> Option<&'a str> {
    let after_from = line.split(" from ").nth(1)?;
    after_from.split_whitespace().next()
}

fn extract_user(line: &str) -> Option<&str> {
    if let Some(after) = line.split("for invalid user ").nth(1) {
        return after.split_whitespace().next();
    }
    if let Some(after) = line.split("for ").nth(1) {
        return after.split_whitespace().next();
    }
    None
}

pub fn parse_line(line: &str) -> Result<SshEvent, ParseError> {
    if line.trim().is_empty() {
        return Err(ParseError::EmptyLine);
    }

   
    if !line.contains("sshd[") {
        return Err(ParseError::UnknownEvent);
    }

    
    if line.contains("Failed password") {
        let invalid_user = line.contains("invalid user");

        let ip_str = extract_ip(line).ok_or_else(|| {
            ParseError::InvalidIp("missing".to_string())
        })?;
        ip_str
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| ParseError::InvalidIp(ip_str.to_string()))?;

        let user = extract_user(line)
            .ok_or_else(|| ParseError::InvalidUser("missing".to_string()))?;

        return Ok(SshEvent::FailedAuth {
            user: user.to_string(),
            ip: ip_str.to_string(),
            invalid_user,
        });
    }

    if line.contains("Accepted password") {
        let ip_str = extract_ip(line).ok_or_else(|| {
            ParseError::InvalidIp("missing".to_string())
        })?;
        ip_str
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| ParseError::InvalidIp(ip_str.to_string()))?;

        let user = extract_user(line)
            .ok_or_else(|| ParseError::InvalidUser("missing".to_string()))?;

        return Ok(SshEvent::SuccessAuth {
            user: user.to_string(),
            ip: ip_str.to_string(),
        });
    }

    Ok(SshEvent::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_failed_auth() {
        let line = "Oct  5 10:15:01 server sshd[12345]: Failed password for Hacker02 from 192.168.10.23 port 22 ssh2";
        let result = parse_line(line).unwrap();
        assert!(matches!(
            result,
            SshEvent::FailedAuth {
                ref user,
                ref ip,
                invalid_user: false,
            } if user == "Hacker02" && ip == "192.168.10.23"
        ));
    }

    #[test]
    fn test_parse_success_auth() {
        let line = "Oct  5 10:15:10 server sshd[12347]: Accepted password for vischenzisch from 192.168.10.200 port 22 ssh2";
        let result = parse_line(line).unwrap();
        assert!(matches!(
            result,
            SshEvent::SuccessAuth {
                ref user,
                ref ip,
            } if user == "vischenzisch" && ip == "192.168.10.200"
        ));
    }

    #[test]
    fn test_parse_empty_line() {
        let result = parse_line("");
        assert!(matches!(result, Err(ParseError::EmptyLine)));
    }

    #[test]
    fn test_parse_corrupted_line() {
        let line = "Oct  5 10:15:50 server kernel: corrupted line without sshd marker";
        let result = parse_line(line);
        assert!(matches!(result, Err(ParseError::UnknownEvent)));
    }
}
