//! Shared interfaces and interface identifiers for the account contracts.
//!
//! The traits mirror the Starknet account surface used by SNIP-6 and the protocol-level
//! deployment and declaration hooks. Public-key accessors are split by key layout so
//! single-felt and array-encoded accounts can expose natural return types.

use starknet::ClassHash;
use starknet::account::Call;

/// SRC5 interface identifier used by Starknet account tooling for interface detection.
pub const ISRC5_ID: felt252 = 0x3f918d17e5ee77373b56385708f855659a07f75997f365cf87748628532a055;

/// SNIP-6 account interface identifier.
pub const ISRC6_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;

/// Common account entrypoints for invoke, declare, signature checks, and SRC5 detection.
#[starknet::interface]
pub trait IPqAccount<TState> {
    /// Executes calls forwarded by the account after protocol validation succeeds.
    fn __execute__(self: @TState, calls: Array<Call>);

    /// Validates an invoke transaction using the current transaction hash and signature.
    fn __validate__(self: @TState, calls: Array<Call>) -> felt252;

    /// Validates a declare transaction using the current transaction hash and signature.
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;

    /// Verifies a signature for an arbitrary hash using the account verifier.
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;

    /// Reports support for SRC5 and SNIP-6 account interfaces.
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
}

/// Deploy-account validation for accounts whose constructor key is a single felt.
#[starknet::interface]
pub trait ISingleFeltDeployable<TState> {
    /// Validates a deploy-account transaction for single-felt-key accounts.
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, public_key: felt252,
    ) -> felt252;
}

/// Deploy-account validation for accounts whose constructor key is an array of felts.
#[starknet::interface]
pub trait IFeltArrayDeployable<TState> {
    /// Validates a deploy-account transaction for array-key accounts.
    fn __validate_deploy__(
        self: @TState,
        class_hash: felt252,
        contract_address_salt: felt252,
        public_key: Array<felt252>,
    ) -> felt252;
}

/// Public-key reader for single-felt-key accounts.
#[starknet::interface]
pub trait ISingleFeltPublicKey<TState> {
    /// Returns the public key felt used by the account verifier.
    fn get_public_key(self: @TState) -> felt252;
}

/// Public-key management for array-key accounts.
#[starknet::interface]
pub trait IFeltArrayPublicKey<TState> {
    /// Returns the public key felts used by the account verifier.
    fn get_public_key(self: @TState) -> Array<felt252>;

    /// Replaces the public key. Callable only by the account itself, so the current key
    /// authorizes the change through `__execute__`. `signature` must be a valid signature
    /// by `new_public_key` of [`get_public_key_rotation_hash`]`(new_public_key)`, which
    /// proves the new key is held and is well formed before it is installed.
    fn set_public_key(ref self: TState, new_public_key: Array<felt252>, signature: Array<felt252>);

    /// The message hash `new_public_key` must sign for [`set_public_key`]: the Poseidon hash
    /// of the rotation domain tag, the chain id, this account's address, and the Poseidon
    /// hashes of the current and the new key.
    fn get_public_key_rotation_hash(self: @TState, new_public_key: Array<felt252>) -> felt252;
}

/// Class upgrades for accounts.
#[starknet::interface]
pub trait IUpgradeable<TState> {
    /// Replaces the account's class with `new_class_hash`, which must be nonzero. Callable
    /// only by the account itself, so the current key authorizes it through `__execute__`.
    fn upgrade(ref self: TState, new_class_hash: ClassHash);
}
