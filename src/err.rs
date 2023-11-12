#[derive(Debug)]
pub enum Error {
    Io(String),
    Input(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Error {
        Error::Io(e.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(msg) => write!(f, "Error::Io({})", msg),
            Error::Input(msg) => write!(f, "Error::Input({})", msg),
        }
    }
}

pub fn input<T>(msg: String) -> Result<T> {
    Err(Error::Input(msg))
}
