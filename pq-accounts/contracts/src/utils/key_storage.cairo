//! Array public-key storage in consecutive slots.
//!
//! The key lives at one fixed storage base: slot 0 holds its length and slots `1..=len`
//! hold its felts. Every slot address is `base + offset`, so reading the key costs one
//! storage read per felt and no address hashing. Offsets are `u8`, which bounds a key to
//! [`MAX_PUBLIC_KEY_FELTS`] felts. The base is derived from a name no contract storage
//! member in this package uses, the same way Cairo derives storage-member bases.

use starknet::SyscallResultTrait;
use starknet::storage_access::{
    StorageBaseAddress, storage_address_from_base_and_offset, storage_base_address_from_felt252,
};
use starknet::syscalls::{storage_read_syscall, storage_write_syscall};

/// Largest key length the slot layout can hold (offsets `1..=255`).
pub const MAX_PUBLIC_KEY_FELTS: u32 = 255;

/// Error raised when a key does not fit the slot layout.
pub const PUBLIC_KEY_TOO_LONG: felt252 = 'Account: public key too long';

fn base() -> StorageBaseAddress {
    storage_base_address_from_felt252(selector!("PqAccount_public_key"))
}

fn read_slot(base: StorageBaseAddress, offset: u8) -> felt252 {
    storage_read_syscall(0, storage_address_from_base_and_offset(base, offset)).unwrap_syscall()
}

fn write_slot(base: StorageBaseAddress, offset: u8, value: felt252) {
    storage_write_syscall(0, storage_address_from_base_and_offset(base, offset), value)
        .unwrap_syscall();
}

/// Stores `public_key`, replacing any previous key. Slots a longer previous key used past
/// the new length are cleared. Panics with [`PUBLIC_KEY_TOO_LONG`] for more than
/// [`MAX_PUBLIC_KEY_FELTS`] felts.
pub fn write_public_key(mut public_key: Span<felt252>) {
    let len = public_key.len();
    assert(len <= MAX_PUBLIC_KEY_FELTS, PUBLIC_KEY_TOO_LONG);
    let base = base();
    let previous_len: u32 = read_slot(base, 0).try_into().unwrap();
    write_slot(base, 0, len.into());
    // `len <= 255`, so every offset below fits a u8.
    let mut offset: u32 = 1;
    while let Some(felt) = public_key.pop_front() {
        write_slot(base, offset.try_into().unwrap(), *felt);
        offset += 1;
    }
    let mut stale: u32 = len + 1;
    while stale <= previous_len {
        write_slot(base, stale.try_into().unwrap(), 0);
        stale += 1;
    }
}

/// The stored key, in the order it was written. Empty before any key is stored.
pub fn read_public_key() -> Array<felt252> {
    let base = base();
    let len: u8 = read_slot(base, 0).try_into().unwrap();
    let mut public_key: Array<felt252> = array![];
    let mut offset: u8 = 0;
    while offset != len {
        offset += 1;
        public_key.append(read_slot(base, offset));
    }
    public_key
}

#[cfg(test)]
mod tests {
    use super::{MAX_PUBLIC_KEY_FELTS, base, read_public_key, read_slot, write_public_key};

    fn ramp(len: u32) -> Array<felt252> {
        let mut out = array![];
        for i in 0..len {
            out.append((i + 1).into());
        }
        out
    }

    #[test]
    fn test_empty_before_first_write() {
        assert_eq!(read_public_key(), array![]);
    }

    #[test]
    fn test_roundtrip_and_shrink_clears_stale_slots() {
        write_public_key(ramp(29).span());
        assert_eq!(read_public_key(), ramp(29));
        write_public_key(array![7, 8].span());
        assert_eq!(read_public_key(), array![7, 8]);
        // Slots 3..=29 of the longer key are cleared.
        let base = base();
        let mut offset: u8 = 3;
        while offset != 30 {
            assert_eq!(read_slot(base, offset), 0);
            offset += 1;
        }
        write_public_key(ramp(29).span());
        assert_eq!(read_public_key(), ramp(29));
    }

    #[test]
    fn test_maximum_length() {
        write_public_key(ramp(MAX_PUBLIC_KEY_FELTS).span());
        assert_eq!(read_public_key(), ramp(MAX_PUBLIC_KEY_FELTS));
    }

    #[test]
    #[should_panic(expected: 'Account: public key too long')]
    fn test_rejects_overlong_key() {
        write_public_key(ramp(MAX_PUBLIC_KEY_FELTS + 1).span());
    }
}
