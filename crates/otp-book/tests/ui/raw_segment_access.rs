use otp_book::Book;
use otp_types::SegmentIndex;

fn main() {
    let book = Book::open(std::path::Path::new("book")).unwrap();
    let segment = book.read_segment(SegmentIndex::new(0)).unwrap();
    let _ = segment.as_bytes();
}
