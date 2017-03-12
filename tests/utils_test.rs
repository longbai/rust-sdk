extern crate qiniu;

use qiniu::utils;

#[test]
fn crc32_bytes() {
    assert_eq!(utils::crc32_bytes(b"Hello, World!"), 3964322768);
}