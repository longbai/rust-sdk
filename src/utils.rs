#![deny(warnings)]
extern crate crc;

use self::crc::crc32;

pub fn crc32_bytes(bytes: &[u8]) -> u32 {
	return crc32::checksum_ieee(bytes);
}


