//! Reusable account component for verifiers behind the `PqSignatureVerifier` interface.
//!
//! [`PqAccountComponent`] carries the complete account flow shared by every array-key
//! account in this package: public-key storage in consecutive slots (`key_storage`), the
//! SNIP-6 entrypoints (`__execute__`, `__validate__`, `__validate_declare__`,
//! `is_valid_signature`, `supports_interface`), deploy-account validation, public-key reads
//! and rotation, and class upgrades. It is generic over the verifier implementation, so a
//! concrete account contract is an embedding of this component with the scheme it
//! authenticates with — see the modules under `accounts/` for the per-scheme
//! instantiations.
//!
//! Every key the component stores has passed the verifier's `is_valid_public_key`. Key
//! rotation and upgrades are self-calls: they run only from `__execute__` in a transaction
//! the current key validated, and a new key must also sign the rotation hash.

#[starknet::component]
pub mod PqAccountComponent {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use pqbench_interface::PqSignatureVerifier;
    use starknet::account::Call;
    use starknet::{ClassHash, SyscallResultTrait};
    use crate::utils::interface::{
        IFeltArrayDeployable, IFeltArrayPublicKey, IPqAccount, IUpgradeable,
    };
    use crate::utils::{execution, key_storage};

    #[storage]
    pub struct Storage {}

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    pub enum Event {
        PublicKeyAdded: PublicKeyAdded,
        PublicKeyRemoved: PublicKeyRemoved,
        Upgraded: Upgraded,
    }

    /// A public key was installed. `key_hash` is the Poseidon hash of its felts.
    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct PublicKeyAdded {
        #[key]
        pub key_hash: felt252,
    }

    /// A public key was replaced. `key_hash` is the Poseidon hash of its felts.
    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct PublicKeyRemoved {
        #[key]
        pub key_hash: felt252,
    }

    /// The account's class was replaced with `class_hash`.
    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct Upgraded {
        pub class_hash: ClassHash,
    }

    #[embeddable_as(AccountImpl)]
    impl Account<
        TContractState,
        impl Verifier: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IPqAccount<ComponentState<TContractState>> {
        fn __execute__(self: @ComponentState<TContractState>, calls: Array<Call>) {
            execution::assert_protocol_caller();
            execution::assert_valid_tx_version();
            execution::execute_calls(calls.span());
        }

        fn __validate__(self: @ComponentState<TContractState>, calls: Array<Call>) -> felt252 {
            let _ = calls;
            validate_transaction::<Verifier>()
        }

        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252,
        ) -> felt252 {
            let _ = class_hash;
            validate_transaction::<Verifier>()
        }

        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            let public_key = key_storage::read_public_key();
            execution::signature_result(Verifier::verify(hash, public_key.span(), signature.span()))
        }

        fn supports_interface(
            self: @ComponentState<TContractState>, interface_id: felt252,
        ) -> bool {
            execution::supports_account_interface(interface_id)
        }
    }

    #[embeddable_as(DeployableImpl)]
    impl Deployable<
        TContractState,
        impl Verifier: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IFeltArrayDeployable<ComponentState<TContractState>> {
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: Array<felt252>,
        ) -> felt252 {
            let _ = class_hash;
            let _ = contract_address_salt;
            let _ = public_key;
            validate_transaction::<Verifier>()
        }
    }

    #[embeddable_as(PublicKeyImpl)]
    impl PublicKey<
        TContractState,
        impl Verifier: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IFeltArrayPublicKey<ComponentState<TContractState>> {
        fn get_public_key(self: @ComponentState<TContractState>) -> Array<felt252> {
            key_storage::read_public_key()
        }

        fn set_public_key(
            ref self: ComponentState<TContractState>,
            new_public_key: Array<felt252>,
            signature: Array<felt252>,
        ) {
            execution::assert_self_caller();
            assert(
                Verifier::is_valid_public_key(new_public_key.span()), execution::INVALID_PUBLIC_KEY,
            );
            let current_key = key_storage::read_public_key();
            let message = rotation_hash(current_key.span(), new_public_key.span());
            assert(
                Verifier::verify(message, new_public_key.span(), signature.span()),
                execution::INVALID_KEY_PROOF,
            );
            key_storage::write_public_key(new_public_key.span());
            self.emit(PublicKeyRemoved { key_hash: poseidon_hash_span(current_key.span()) });
            self.emit(PublicKeyAdded { key_hash: poseidon_hash_span(new_public_key.span()) });
        }

        fn get_public_key_rotation_hash(
            self: @ComponentState<TContractState>, new_public_key: Array<felt252>,
        ) -> felt252 {
            let current_key = key_storage::read_public_key();
            rotation_hash(current_key.span(), new_public_key.span())
        }
    }

    #[embeddable_as(UpgradeableImpl)]
    impl Upgradeable<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of IUpgradeable<ComponentState<TContractState>> {
        fn upgrade(ref self: ComponentState<TContractState>, new_class_hash: ClassHash) {
            execution::assert_self_caller();
            assert(!new_class_hash.is_zero(), execution::INVALID_CLASS_HASH);
            starknet::syscalls::replace_class_syscall(new_class_hash).unwrap_syscall();
            self.emit(Upgraded { class_hash: new_class_hash });
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        impl Verifier: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        /// Stores the public key the embedded verifier validates against. Panics with
        /// `Account: invalid public key` unless the verifier accepts the key's layout.
        fn initializer(ref self: ComponentState<TContractState>, public_key: Array<felt252>) {
            assert(Verifier::is_valid_public_key(public_key.span()), execution::INVALID_PUBLIC_KEY);
            key_storage::write_public_key(public_key.span());
            self.emit(PublicKeyAdded { key_hash: poseidon_hash_span(public_key.span()) });
        }

        /// Validates the current transaction hash against the transaction signature.
        fn validate_transaction(self: @ComponentState<TContractState>) -> felt252 {
            validate_transaction::<Verifier>()
        }

        /// The stored public key in the verifier's packed felt layout.
        fn read_public_key(self: @ComponentState<TContractState>) -> Array<felt252> {
            key_storage::read_public_key()
        }
    }

    /// Validates the current transaction hash against the transaction signature with the
    /// stored key, panicking with `Account: invalid signature` if it does not verify.
    fn validate_transaction<impl Verifier: PqSignatureVerifier>() -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        let public_key = key_storage::read_public_key();
        execution::assert_valid_signature(
            Verifier::verify(tx_info.transaction_hash, public_key.span(), tx_info.signature),
        )
    }

    /// Poseidon hash of the rotation domain tag, the chain id, this account's address, and
    /// the Poseidon hashes of the current and the new key.
    fn rotation_hash(current_key: Span<felt252>, new_key: Span<felt252>) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        poseidon_hash_span(
            array![
                execution::PUBLIC_KEY_ROTATION_DOMAIN, tx_info.chain_id,
                starknet::get_contract_address().into(), poseidon_hash_span(current_key),
                poseidon_hash_span(new_key),
            ]
                .span(),
        )
    }
}
