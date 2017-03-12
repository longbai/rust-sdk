extern crate qiniu;

use qiniu::utils;

#[test]
fn crc32_bytes() {
    assert_eq!(utils::crc32_bytes(b"Hello, World!"), 3964322768);
}

#[test]
fn base64_encode(){
	assert_eq!(&*(utils::base64_encode("你好/+=".as_bytes())), "5L2g5aW9Lys9");
}
