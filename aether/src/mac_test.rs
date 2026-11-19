use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::Blake2sMac;
use blake2::{Blake2s256, Digest};

pub fn b2s_keyed_mac_16(key: &[u8], data1: &[u8]) -> [u8; 16] {
    let mut hmac = <Blake2sMac<blake2::digest::consts::U16>>::new_from_slice(key).unwrap();
    Update::update(&mut hmac, data1);
    hmac.finalize_fixed().into()
}
