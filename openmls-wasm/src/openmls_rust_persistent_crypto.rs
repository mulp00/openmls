//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use wasm_bindgen::JsError;
use super::persistent_key_store::PersistentKeyStore;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

#[derive(Default, Debug)]
pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    key_store: PersistentKeyStore,
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = PersistentKeyStore;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}

impl OpenMlsRustPersistentCrypto {
    pub fn serialize(&self) -> Result<String, JsError> {
        self.key_store.serialize()
    }

    pub fn deserialize(json_str: &str) -> Result<OpenMlsRustPersistentCrypto, JsError> {
        let key_store = PersistentKeyStore::deserialize(json_str)?;
        Ok(OpenMlsRustPersistentCrypto {
            crypto: RustCrypto::default(),
            key_store,
        })
    }
}
