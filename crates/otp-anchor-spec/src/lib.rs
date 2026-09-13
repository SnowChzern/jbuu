//! Canonical OTP anchor records and deterministic two-copy recovery decisions.

#![forbid(unsafe_code)]

use core::cmp::Ordering;
use otp_types::{BookId, Generation, SegmentIndex};
use sha2::{Digest, Sha256};

pub const ANCHOR_RECORD_LEN: usize = 104;
const PREFIX_LEN: usize = 72;
const MAGIC: &[u8; 4] = b"OTPA";
const VERSION: u16 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SegmentHash(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorPayload {
    Init,
    Intent { reserved: SegmentIndex },
    Commit { previous_segment_hash: SegmentHash },
}

impl AnchorPayload {
    const fn tag(self) -> u8 {
        match self {
            Self::Init => 0,
            Self::Intent { .. } => 1,
            Self::Commit { .. } => 2,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AnchorRecord {
    pub book_id: BookId,
    pub next: SegmentIndex,
    pub generation: Generation,
    pub payload: AnchorPayload,
}

impl AnchorRecord {
    pub const fn init(book_id: BookId) -> Self {
        Self {
            book_id,
            next: SegmentIndex::ZERO,
            generation: Generation::new(0),
            payload: AnchorPayload::Init,
        }
    }

    pub fn intent(book_id: BookId, generation: Generation, reserved: SegmentIndex) -> Self {
        Self {
            book_id,
            next: reserved.next(),
            generation,
            payload: AnchorPayload::Intent { reserved },
        }
    }

    pub fn commit(
        book_id: BookId,
        generation: Generation,
        next: SegmentIndex,
        previous_segment_hash: SegmentHash,
    ) -> Self {
        Self {
            book_id,
            next,
            generation,
            payload: AnchorPayload::Commit {
                previous_segment_hash,
            },
        }
    }

    /// Frozen order: generation first, then INIT < INTENT < COMMIT.
    pub fn state_cmp(&self, other: &Self) -> Ordering {
        (self.generation, self.payload.tag()).cmp(&(other.generation, other.payload.tag()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorCopy {
    A,
    B,
}

pub trait AnchorStore {
    type Error;
    fn read_verified(&mut self) -> Result<AnchorRecord, Self::Error>;
    fn write_full_and_sync(&mut self, record: &AnchorRecord) -> Result<(), Self::Error>;
    fn sync_parent_if_created(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadFailure {
    Corrupt,
    Unreadable,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorSpecError {
    DecodeFailed { reason: &'static str },
    IntegrityCheckFailed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryDecision {
    Consistent(AnchorRecord),
    AdoptHigher {
        adopted: AnchorRecord,
        stale: AnchorCopy,
    },
    QuarantineCorrupt {
        copy: AnchorCopy,
        reason: &'static str,
    },
    CannotProveSafe {
        reason: &'static str,
    },
    BothUnreadable,
}

pub fn encode_record(record: &AnchorRecord, out: &mut Vec<u8>) {
    let mut bytes = [0u8; ANCHOR_RECORD_LEN];
    bytes[0..4].copy_from_slice(MAGIC);
    bytes[4..6].copy_from_slice(&VERSION.to_be_bytes());
    bytes[6] = record.payload.tag();
    bytes[8..24].copy_from_slice(record.book_id.as_bytes());
    bytes[24..32].copy_from_slice(&record.generation.get().to_be_bytes());
    bytes[32..40].copy_from_slice(&record.next.get().to_be_bytes());
    match record.payload {
        AnchorPayload::Init => {}
        AnchorPayload::Intent { reserved } => {
            bytes[40..48].copy_from_slice(&reserved.get().to_be_bytes());
        }
        AnchorPayload::Commit {
            previous_segment_hash,
        } => bytes[40..72].copy_from_slice(&previous_segment_hash.0),
    }
    let digest = Sha256::digest(&bytes[..PREFIX_LEN]);
    bytes[PREFIX_LEN..].copy_from_slice(&digest);
    out.extend_from_slice(&bytes);
}

pub fn decode_and_verify(buf: &[u8]) -> Result<AnchorRecord, AnchorSpecError> {
    if buf.len() != ANCHOR_RECORD_LEN {
        return decode_err("length");
    }
    if &buf[0..4] != MAGIC {
        return decode_err("magic");
    }
    if u16::from_be_bytes([buf[4], buf[5]]) != VERSION {
        return decode_err("version");
    }
    if buf[7] != 0 {
        return decode_err("flags");
    }
    if Sha256::digest(&buf[..PREFIX_LEN]).as_slice() != &buf[PREFIX_LEN..] {
        return Err(AnchorSpecError::IntegrityCheckFailed);
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&buf[8..24]);
    let generation = Generation::new(be_u64(&buf[24..32]));
    let next = SegmentIndex::new(be_u64(&buf[32..40]));
    let payload = match buf[6] {
        0 => {
            if generation.get() != 0 || next.get() != 0 || buf[40..72].iter().any(|b| *b != 0) {
                return decode_err("non-canonical-init");
            }
            AnchorPayload::Init
        }
        1 => {
            if next.get() == 0 || buf[48..72].iter().any(|b| *b != 0) {
                return decode_err("non-canonical-intent");
            }
            let reserved = SegmentIndex::new(be_u64(&buf[40..48]));
            if reserved.get().checked_add(1) != Some(next.get()) {
                return decode_err("intent-index");
            }
            AnchorPayload::Intent { reserved }
        }
        2 => {
            if next.get() == 0 {
                return decode_err("non-canonical-commit");
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&buf[40..72]);
            AnchorPayload::Commit {
                previous_segment_hash: SegmentHash(hash),
            }
        }
        _ => return decode_err("record-type"),
    };
    Ok(AnchorRecord {
        book_id: BookId::from_bytes(id),
        next,
        generation,
        payload,
    })
}

pub fn decide(
    a: Result<AnchorRecord, ReadFailure>,
    b: Result<AnchorRecord, ReadFailure>,
) -> RecoveryDecision {
    match (a, b) {
        (Err(ReadFailure::Unreadable), Err(ReadFailure::Unreadable)) => {
            RecoveryDecision::BothUnreadable
        }
        (Err(_), Ok(_)) => RecoveryDecision::QuarantineCorrupt {
            copy: AnchorCopy::A,
            reason: "anchor-a-invalid",
        },
        (Ok(_), Err(_)) => RecoveryDecision::QuarantineCorrupt {
            copy: AnchorCopy::B,
            reason: "anchor-b-invalid",
        },
        (Err(_), Err(_)) => RecoveryDecision::CannotProveSafe {
            reason: "both-anchors-invalid",
        },
        (Ok(a), Ok(b)) => {
            if a.book_id != b.book_id {
                return RecoveryDecision::CannotProveSafe {
                    reason: "book-id-mismatch",
                };
            }
            match a.state_cmp(&b) {
                Ordering::Equal if a == b => RecoveryDecision::Consistent(a),
                Ordering::Equal => RecoveryDecision::CannotProveSafe {
                    reason: "same-order-different-bytes",
                },
                Ordering::Greater if a.next >= b.next => RecoveryDecision::AdoptHigher {
                    adopted: a,
                    stale: AnchorCopy::B,
                },
                Ordering::Less if b.next >= a.next => RecoveryDecision::AdoptHigher {
                    adopted: b,
                    stale: AnchorCopy::A,
                },
                _ => RecoveryDecision::CannotProveSafe {
                    reason: "order-contradiction",
                },
            }
        }
    }
}

fn be_u64(bytes: &[u8]) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(bytes);
    u64::from_be_bytes(value)
}

fn decode_err<T>(reason: &'static str) -> Result<T, AnchorSpecError> {
    Err(AnchorSpecError::DecodeFailed { reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .flat_map(|part| {
                (0..part.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&part[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    #[test]
    fn frozen_golden_records_match() {
        let segment_hash = SegmentHash(
            hex("fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108")
                .try_into()
                .unwrap(),
        );
        let cases = [
            (
                AnchorRecord::init(ID),
                "e7b9b5274ccaa9515f731468cf39a77f4dd7854b1e90cabd214c86a49cfb7cbd",
            ),
            (
                AnchorRecord::intent(ID, Generation::new(7), SegmentIndex::new(40)),
                "0ed866f85a72ef89e3e93f396e2477e22275c0b4503dbd6842ef21d254a13d1c",
            ),
            (
                AnchorRecord::commit(ID, Generation::new(7), SegmentIndex::new(41), segment_hash),
                "feaa64c277074e34c9b807810268b3ea013141c3a336826050e7e21489e6f62e",
            ),
        ];
        for (record, integrity) in cases {
            let mut encoded = Vec::new();
            encode_record(&record, &mut encoded);
            assert_eq!(&encoded[72..], hex(integrity));
            assert_eq!(decode_and_verify(&encoded).unwrap(), record);
        }
    }

    #[test]
    fn commit_orders_after_intent_in_same_generation() {
        let intent = AnchorRecord::intent(ID, Generation::new(7), SegmentIndex::new(40));
        let commit = AnchorRecord::commit(
            ID,
            Generation::new(7),
            SegmentIndex::new(41),
            SegmentHash([9; 32]),
        );
        assert_eq!(intent.state_cmp(&commit), Ordering::Less);
    }

    #[test]
    fn rejects_noncanonical_and_corrupt_records() {
        let mut encoded = Vec::new();
        encode_record(&AnchorRecord::init(ID), &mut encoded);
        encoded[7] = 1;
        assert!(decode_and_verify(&encoded).is_err());
        encoded[7] = 0;
        encoded[103] ^= 1;
        assert_eq!(
            decode_and_verify(&encoded),
            Err(AnchorSpecError::IntegrityCheckFailed)
        );
    }
}
