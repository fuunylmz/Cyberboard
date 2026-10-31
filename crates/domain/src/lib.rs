//! Domain primitives shared by the control plane and background workers.
//!
//! The initial crate intentionally contains no transport or database types. Keeping
//! these errors and identifiers independent makes it possible to evolve the API,
//! worker, and agent without coupling business rules to Axum or SQLx.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub type DomainResult<T> = Result<T, DomainError>;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("resource not found")]
    NotFound,

    #[error("resource conflict: {0}")]
    Conflict(String),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(Uuid);

impl NodeId {
    pub fn new(value: Uuid) -> Self {
        Self(value)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::NodeId;
    use uuid::Uuid;

    #[test]
    fn node_id_round_trips() {
        let uuid = Uuid::new_v4();
        assert_eq!(NodeId::new(uuid).as_uuid(), uuid);
    }
}
