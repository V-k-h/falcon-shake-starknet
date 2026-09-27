//! Falcon-512 SHAKE-256 account contract.
//!
//! This account stores the packed 29-felt NTT-domain public key and validates the same
//! 60-felt hint signature layout as the hint account, deriving the message point with the
//! SHAKE-256 hash-to-point of the Falcon round-3 specification, so round-3 Falcon signers
//! (falcon.py, PQClean, liboqs) need no custom hash construction.

#[starknet::contract(account)]
pub mod Falcon512ShakeAccount {
    use pqbench_falcon_512::Falcon512ShakeVerifier;
    use crate::utils::account::PqAccountComponent;

    component!(path: PqAccountComponent, storage: account, event: AccountEvent);

    #[abi(embed_v0)]
    impl AccountImpl =
        PqAccountComponent::AccountImpl<ContractState, Falcon512ShakeVerifier>;
    #[abi(embed_v0)]
    impl DeployableImpl =
        PqAccountComponent::DeployableImpl<ContractState, Falcon512ShakeVerifier>;
    #[abi(embed_v0)]
    impl PublicKeyImpl =
        PqAccountComponent::PublicKeyImpl<ContractState, Falcon512ShakeVerifier>;
    #[abi(embed_v0)]
    impl UpgradeableImpl = PqAccountComponent::UpgradeableImpl<ContractState>;

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

    /// Initializes the account with the packed Falcon public key used for validation.
    /// Panics with `Account: invalid public key` unless it is a canonical 29-felt key.
    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        self.account.initializer(public_key);
    }
}
