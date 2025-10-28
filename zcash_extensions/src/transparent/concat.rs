//! String concatenation TZE demonstration.
//!
//! This extension implements a simple string concatenation constraint:
//!
//! > A TZE output is locked with an expected concatenation result.
//! > To spend it, you must provide two strings that concatenate to the expected result.
//!
//! This demonstrates the basic structure of a TZE extension with:
//! - A single mode (Mode 0: concat)
//! - Simple precondition (expected result string)
//! - Simple witness (two strings to concatenate)
//! - Minimal context requirements
//!
//! Transaction format:
//! - `tx_a`: `[ [any input types...] ----> TzeOut(value, expected_string) ]`
//! - `tx_b`: `[ TzeIn(tx_a, (string_a, string_b)) -> [any output types...] ]`

#![cfg(zcash_unstable = "zfuture")]

use std::fmt;

use zcash_primitives::{
    extensions::transparent::{Extension, ExtensionTxBuilder, FromPayload, ToPayload},
    transaction::components::tze::{OutPoint, TzeOut},
};
use zcash_protocol::value::Zatoshis;

/// Mode 0: String concatenation
mod concat {
    pub const MODE: u32 = 0;

    /// Precondition: Expected concatenation result
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Precondition(pub Vec<u8>);

    /// Witness: Two strings to concatenate
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Witness {
        pub string_a: Vec<u8>,
        pub string_b: Vec<u8>,
    }
}

/// All possible preconditions for the concat extension
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    Concat(concat::Precondition),
}

impl Precondition {
    /// Convenience constructor for concat precondition
    pub fn concat(expected: Vec<u8>) -> Self {
        Precondition::Concat(concat::Precondition(expected))
    }
}

impl FromPayload for Precondition {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            concat::MODE => Ok(Precondition::Concat(concat::Precondition(
                payload.to_vec(),
            ))),
            m => Err(Error::UnknownMode(m)),
        }
    }
}

impl ToPayload for Precondition {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Precondition::Concat(p) => (concat::MODE, p.0.clone()),
        }
    }
}

/// All possible witnesses for the concat extension
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Witness {
    Concat(concat::Witness),
}

impl Witness {
    /// Convenience constructor for concat witness
    pub fn concat(string_a: Vec<u8>, string_b: Vec<u8>) -> Self {
        Witness::Concat(concat::Witness { string_a, string_b })
    }
}

impl FromPayload for Witness {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            concat::MODE => {
                // Payload format: [len_a: 4 bytes][string_a][string_b]
                if payload.len() < 4 {
                    return Err(Error::InvalidPayload("payload too short".into()));
                }

                let len_a_u32 = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let len_a = usize::try_from(len_a_u32)
                    .map_err(|_| Error::InvalidPayload("string_a length exceeds platform limit".into()))?;

                if payload.len() < 4 + len_a {
                    return Err(Error::InvalidPayload("string_a truncated".into()));
                }

                let string_a = payload[4..4 + len_a].to_vec();
                let string_b = payload[4 + len_a..].to_vec();

                Ok(Witness::Concat(concat::Witness { string_a, string_b }))
            }
            m => Err(Error::UnknownMode(m)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Witness::Concat(w) => {
                // Note: We truncate lengths > u32::MAX to u32::MAX.
                // In practice, payloads this large are not feasible.
                let len_a = u32::try_from(w.string_a.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes();
                let mut payload = Vec::with_capacity(4 + w.string_a.len() + w.string_b.len());
                payload.extend_from_slice(&len_a);
                payload.extend_from_slice(&w.string_a);
                payload.extend_from_slice(&w.string_b);
                (concat::MODE, payload)
            }
        }
    }
}

/// Errors that can occur during concat extension verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The mode value is not recognized by this extension
    UnknownMode(u32),
    /// The payload could not be parsed
    InvalidPayload(String),
    /// The concatenation result doesn't match the expected value
    ConcatMismatch,
    /// Mode mismatch between precondition and witness
    ModeMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownMode(m) => write!(f, "unknown mode: {}", m),
            Error::InvalidPayload(msg) => write!(f, "invalid payload: {}", msg),
            Error::ConcatMismatch => write!(f, "concatenation result doesn't match expected value"),
            Error::ModeMismatch => write!(f, "precondition and witness modes don't match"),
        }
    }
}

impl std::error::Error for Error {}

/// Context trait for the concat extension.
///
/// For this simple extension, we don't need any information from the transaction.
pub trait Context {}

// Blanket implementation: any type can serve as context
impl<T> Context for T {}

/// The concat extension program.
///
/// This implements the [`Extension`] trait to verify that witness strings
/// concatenate to the expected precondition value.
pub struct Program;

impl<C: Context> Extension<C> for Program {
    type Precondition = Precondition;
    type Witness = Witness;
    type Error = Error;

    fn verify_inner(
        &self,
        precondition: &Self::Precondition,
        witness: &Self::Witness,
        _context: &C,
    ) -> Result<(), Self::Error> {
        match (precondition, witness) {
            (Precondition::Concat(p), Witness::Concat(w)) => {
                // Perform concatenation
                let mut actual = w.string_a.clone();
                actual.extend_from_slice(&w.string_b);

                // Verify it matches expected result
                if actual == p.0 {
                    Ok(())
                } else {
                    Err(Error::ConcatMismatch)
                }
            }
        }
    }
}

/// Builder wrapper for constructing transactions with the concat extension.
///
/// This wraps any [`ExtensionTxBuilder`] to provide convenient methods for
/// adding concat-specific inputs and outputs.
pub struct ConcatBuilder<B> {
    /// The underlying transaction builder
    pub txn_builder: B,
    /// The extension ID for the concat extension
    pub extension_id: u32,
}

impl<'a, B: ExtensionTxBuilder<'a>> ConcatBuilder<B> {
    /// Add a concat output: locks funds with an expected concatenation result
    ///
    /// To spend this output, a subsequent transaction must provide two strings
    /// that concatenate to the expected result.
    pub fn concat_output(
        &mut self,
        value: Zatoshis,
        expected: Vec<u8>,
    ) -> Result<(), B::BuildError> {
        self.txn_builder
            .add_tze_output(self.extension_id, value, &Precondition::concat(expected))
    }

    /// Add a concat input: spends a concat output by providing two strings
    ///
    /// The two strings must concatenate to the expected result locked in the
    /// referenced output.
    pub fn concat_input(
        &mut self,
        prevout: (OutPoint, TzeOut),
        string_a: Vec<u8>,
        string_b: Vec<u8>,
    ) -> Result<(), B::BuildError> {
        self.txn_builder.add_tze_input(
            self.extension_id,
            concat::MODE,
            prevout,
            |_| Ok(Witness::concat(string_a, string_b)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper struct for testing
    struct DummyCtx;

    #[test]
    fn precondition_concat_round_trip() {
        let expected = b"helloworld".to_vec();
        let precond = Precondition::concat(expected.clone());

        let (mode, payload) = precond.to_payload();
        let parsed = Precondition::from_payload(mode, &payload).unwrap();

        assert_eq!(precond, parsed);
        assert_eq!(mode, concat::MODE);
        assert_eq!(payload, expected);
    }

    #[test]
    fn witness_concat_round_trip() {
        let string_a = b"hello".to_vec();
        let string_b = b"world".to_vec();
        let witness = Witness::concat(string_a.clone(), string_b.clone());

        let (mode, payload) = witness.to_payload();
        let parsed = Witness::from_payload(mode, &payload).unwrap();

        assert_eq!(witness, parsed);
        assert_eq!(mode, concat::MODE);
    }

    #[test]
    fn witness_rejects_invalid_payload() {
        // Payload too short (less than 4 bytes for length)
        let result = Witness::from_payload(concat::MODE, &[0, 1, 2]);
        assert!(matches!(result, Err(Error::InvalidPayload(_))));

        // Length indicates more data than available
        let result = Witness::from_payload(concat::MODE, &[10, 0, 0, 0, 1, 2, 3]);
        assert!(matches!(result, Err(Error::InvalidPayload(_))));
    }

    #[test]
    fn precondition_rejects_invalid_mode() {
        let result = Precondition::from_payload(999, &[1, 2, 3]);
        assert_eq!(result, Err(Error::UnknownMode(999)));
    }

    #[test]
    fn witness_rejects_invalid_mode() {
        let result = Witness::from_payload(999, &[1, 2, 3, 4]);
        assert_eq!(result, Err(Error::UnknownMode(999)));
    }

    #[test]
    fn concat_success() {
        let expected = b"helloworld".to_vec();
        let precond = Precondition::concat(expected);
        let witness = Witness::concat(b"hello".to_vec(), b"world".to_vec());

        let result = Program.verify_inner(&precond, &witness, &DummyCtx);
        assert!(result.is_ok());
    }

    #[test]
    fn concat_mismatch() {
        let expected = b"goodbye".to_vec();
        let precond = Precondition::concat(expected);
        let witness = Witness::concat(b"hello".to_vec(), b"world".to_vec());

        let result = Program.verify_inner(&precond, &witness, &DummyCtx);
        assert_eq!(result, Err(Error::ConcatMismatch));
    }

    #[test]
    fn concat_empty_strings() {
        // Both strings empty
        let expected = b"".to_vec();
        let precond = Precondition::concat(expected);
        let witness = Witness::concat(b"".to_vec(), b"".to_vec());

        let result = Program.verify_inner(&precond, &witness, &DummyCtx);
        assert!(result.is_ok());
    }

    #[test]
    fn concat_one_empty_string() {
        // First string empty
        let expected = b"world".to_vec();
        let precond = Precondition::concat(expected);
        let witness = Witness::concat(b"".to_vec(), b"world".to_vec());

        let result = Program.verify_inner(&precond, &witness, &DummyCtx);
        assert!(result.is_ok());

        // Second string empty
        let expected = b"hello".to_vec();
        let precond = Precondition::concat(expected);
        let witness = Witness::concat(b"hello".to_vec(), b"".to_vec());

        let result = Program.verify_inner(&precond, &witness, &DummyCtx);
        assert!(result.is_ok());
    }

    #[test]
    fn concat_with_utf8() {
        // Test with valid UTF-8
        let expected = "Hello, 世界!".as_bytes().to_vec();
        let precond = Precondition::concat(expected);
        let witness = Witness::concat("Hello, ".as_bytes().to_vec(), "世界!".as_bytes().to_vec());

        let result = Program.verify_inner(&precond, &witness, &DummyCtx);
        assert!(result.is_ok());
    }

    #[test]
    fn concat_with_binary_data() {
        // Test with arbitrary binary data (not UTF-8)
        let expected = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
        let precond = Precondition::concat(expected);
        let witness = Witness::concat(vec![0xFF, 0xFE, 0xFD], vec![0xFC, 0xFB, 0xFA]);

        let result = Program.verify_inner(&precond, &witness, &DummyCtx);
        assert!(result.is_ok());
    }

    #[test]
    fn witness_serialization_preserves_data() {
        // Test with various sizes to ensure length encoding works correctly
        let test_cases = vec![
            (vec![0; 0], vec![0; 0]),       // Empty
            (vec![0; 1], vec![0; 1]),       // Small
            (vec![0; 255], vec![0; 255]),   // Medium
            (vec![0; 1000], vec![0; 1000]), // Large
        ];

        for (string_a, string_b) in test_cases {
            let witness = Witness::concat(string_a.clone(), string_b.clone());
            let (mode, payload) = witness.to_payload();
            let parsed = Witness::from_payload(mode, &payload).unwrap();

            let Witness::Concat(w) = parsed;
            assert_eq!(w.string_a, string_a);
            assert_eq!(w.string_b, string_b);
        }
    }
}
