#[test]
fn external_segment_access_is_compile_error() {
    trybuild::TestCases::new().compile_fail("tests/ui/raw_segment_access.rs");
}

#[test]
fn public_surface_has_no_direct_segment_read() {
    let src = include_str!("../src/lib.rs");
    assert!(src.contains("pub(crate) fn read_segment"));
    assert!(!src.contains("pub fn __allocator_read_segment"));
    assert!(!src.contains("pub fn expose_for_allocator"));
}

#[test]
fn compile_fail_fixture_is_registered() {
    let fixture = include_str!("ui/raw_segment_access.rs");
    assert!(fixture.contains("read_segment"));
    assert!(fixture.contains("as_bytes"));
}

#[test]
fn header_constants_frozen() {
    assert_eq!(otp_book::BOOK_MAGIC, *b"OTPB");
    assert_eq!(otp_book::BOOK_VERSION, 1);
    assert_eq!(otp_book::header::HEADER_LEN, 128);
    assert_eq!(otp_book::MAX_SEGMENT_COUNT, (1u64 << 40) - 1);
    assert_eq!(otp_book::header::SEGMENT_AREA_OFFSET, 128);
}
