// 架构夹具（任务 #47）：即使 otp-book 作为 dev-dependency 可达，
// Book::read_segment 仍是 crate-private（E0624）——握手层（含其测试
// 编译单元）不存在绕过 SegmentIssuer 直读密码本段的路径。
use otp_book::Book;
use otp_types::SegmentIndex;

fn main() {
    let book = Book::open(std::path::Path::new("book")).unwrap();
    let segment = book.read_segment(SegmentIndex::new(0)).unwrap();
    let _ = segment.as_bytes();
}
