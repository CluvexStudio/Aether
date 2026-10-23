use thiserror::Error;

#[derive(Error, Debug)]
pub enum AetherError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("quic: {0}")]
    Quic(#[from] quiche::Error),

    #[error("h3: {0}")]
    H3(#[from] quiche::h3::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("ech: {0}")]
    Ech(String),

    #[error("masque: {0}")]
    Masque(String),

    #[error("prober: no clean endpoint found")]
    NoCleanEndpoint,

    #[error("capsule: {0}")]
    Capsule(String),

    #[error("api: {0}")]
    Api(String),

    #[error("identity refused: {0}")]
    IdentityRefused(String),

    #[error("cancelled")]
    Cancelled,

    #[error("other: {0}")]
    Other(String),
}

impl AetherError {
    /// The error's words for a message that wraps them in words of its own: without the label
    /// "other: ", which says nothing there, and with every other kind's label, which does.
    pub fn detail(&self) -> String {
        match self {
            AetherError::Other(message) => message.clone(),
            other => other.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, AetherError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrapped_error_keeps_its_words_and_the_label_of_its_kind_but_other() {
        assert_eq!(AetherError::Other("no port".into()).detail(), "no port");
        assert_eq!(
            AetherError::Tls("bad cipher".into()).detail(),
            "tls: bad cipher"
        );
        assert_eq!(AetherError::Cancelled.detail(), "cancelled");
    }
}
