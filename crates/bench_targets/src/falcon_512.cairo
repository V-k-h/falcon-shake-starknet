//! Benchmark accounts for the Falcon-512 verifier with the standard SHAKE-256
//! hash-to-point — hint and direct variants.
//!
//! Each stores the 29-felt NTT-domain public key in a `Vec` and validates the transaction
//! signature with `pqbench_falcon_512`. The hint account expects a 60-felt signature
//! (packed s1 ‖ salt ‖ packed mul_hint); the direct account a 31-felt one (packed s1 ‖
//! salt). Reading the packed key back is part of the measured validation cost.

#[starknet::contract]
pub mod Falcon512ShakeAccount {
    use pqbench_falcon_512::Falcon512ShakeVerifier;
    use starknet::storage::{MutableVecTrait, StoragePointerReadAccess, Vec, VecTrait};
    use crate::IValidateBench;

    #[storage]
    struct Storage {
        public_key: Vec<felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        for coeff in public_key {
            self.public_key.push(coeff);
        }
    }

    #[abi(embed_v0)]
    impl ValidateBenchImpl of IValidateBench<ContractState> {
        fn validate(self: @ContractState) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let mut public_key = array![];
            let len = self.public_key.len();
            let mut i = 0;
            while i != len {
                public_key.append(self.public_key.at(i).read());
                i += 1;
            }
            let valid = Falcon512ShakeVerifier::verify(
                tx_info.transaction_hash, public_key.span(), tx_info.signature,
            );
            assert!(valid, "invalid signature");
            starknet::VALIDATED
        }
    }
}

#[starknet::contract]
pub mod Falcon512ShakeDirectAccount {
    use pqbench_falcon_512::Falcon512ShakeDirectVerifier;
    use starknet::storage::{MutableVecTrait, StoragePointerReadAccess, Vec, VecTrait};
    use crate::IValidateBench;

    #[storage]
    struct Storage {
        public_key: Vec<felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        for coeff in public_key {
            self.public_key.push(coeff);
        }
    }

    #[abi(embed_v0)]
    impl ValidateBenchImpl of IValidateBench<ContractState> {
        fn validate(self: @ContractState) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let mut public_key = array![];
            let len = self.public_key.len();
            let mut i = 0;
            while i != len {
                public_key.append(self.public_key.at(i).read());
                i += 1;
            }
            let valid = Falcon512ShakeDirectVerifier::verify(
                tx_info.transaction_hash, public_key.span(), tx_info.signature,
            );
            assert!(valid, "invalid signature");
            starknet::VALIDATED
        }
    }
}
