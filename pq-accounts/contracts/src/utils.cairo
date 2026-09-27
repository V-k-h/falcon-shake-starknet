//! Shared building blocks for the accounts: the account interfaces (`interface`), the
//! common execution and validation flow (`execution`), consecutive-slot public-key storage
//! (`key_storage`), and the reusable verifier-generic account component (`account`).

pub mod account;
pub mod execution;
pub mod interface;
pub mod key_storage;
