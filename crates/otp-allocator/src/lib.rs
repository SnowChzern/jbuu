//! Public facade for the allocator implementation hosted by `otp-book`.
//!
//! Keeping the transaction and book reader in one crate makes `Book::read_segment`
//! crate-private in the only crate that can reach it; this facade exposes only the
//! committed issuer API and never exposes a raw book segment.
#![forbid(unsafe_code)]

pub use otp_book::allocator::{
    Allocator, AllocatorConfig, CommittedSegment, IssueError, RangeIssuer, ReservedRange,
    SegmentIssuer,
};
