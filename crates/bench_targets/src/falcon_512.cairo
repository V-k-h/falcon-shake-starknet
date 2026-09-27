//! Benchmark accounts for the Falcon-512 verifier with the standard SHAKE-256
//! hash-to-point — hint and direct variants.
//!
//! Each embeds the production account component (`pq_accounts::utils::account`) with its
//! verifier, so `validate()` runs exactly the deployable accounts' validation path: read
//! the transaction hash and signature, read the 29-felt key from its consecutive storage
//! slots, and verify. The hint account expects a 60-felt signature (packed s1 ‖ salt ‖
//! packed mul_hint); the direct account a 31-felt one (packed s1 ‖ salt).

#[starknet::contract]
pub mod Falcon512ShakeAccount {
    use pq_accounts::utils::account::PqAccountComponent;
    use pqbench_falcon_512::Falcon512ShakeVerifier;
    use crate::IValidateBench;

    component!(path: PqAccountComponent, storage: account, event: AccountEvent);

    impl InternalImpl = PqAccountComponent::InternalImpl<ContractState, Falcon512ShakeVerifier>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: PqAccountComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: PqAccountComponent::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        self.account.initializer(public_key);
    }

    #[abi(embed_v0)]
    impl ValidateBenchImpl of IValidateBench<ContractState> {
        fn validate(self: @ContractState) -> felt252 {
            self.account.validate_transaction()
        }
    }
}

#[starknet::contract]
pub mod Falcon512ShakeDirectAccount {
    use pq_accounts::utils::account::PqAccountComponent;
    use pqbench_falcon_512::Falcon512ShakeDirectVerifier;
    use crate::IValidateBench;

    component!(path: PqAccountComponent, storage: account, event: AccountEvent);

    impl InternalImpl =
        PqAccountComponent::InternalImpl<ContractState, Falcon512ShakeDirectVerifier>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: PqAccountComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: PqAccountComponent::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        self.account.initializer(public_key);
    }

    #[abi(embed_v0)]
    impl ValidateBenchImpl of IValidateBench<ContractState> {
        fn validate(self: @ContractState) -> felt252 {
            self.account.validate_transaction()
        }
    }
}
