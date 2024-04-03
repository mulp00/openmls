use std::{
    collections::HashMap

    ,
    sync::RwLock,
};

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsError;

use openmls_traits::key_store::{MlsEntity, OpenMlsKeyStore};

use base64::engine::Engine;
use base64::engine::general_purpose::STANDARD;

#[derive(Debug, Default)]
pub struct PersistentKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableKeyStore {
    values: HashMap<String, String>,
}

impl OpenMlsKeyStore for PersistentKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = PersistentKeyStoreError;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let value =
            serde_json::to_vec(v).map_err(|_| PersistentKeyStoreError::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k.to_vec(), value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(k) {
            serde_json::from_slice(value).ok()
        } else {
            None
        }
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(k);
        Ok(())
    }
}

impl PersistentKeyStore {

    pub fn serialize(&self) -> Result<String, JsError> {
        let values = self.values.read().unwrap();
        let mut serializable_values = HashMap::new();
        for (k, v) in values.iter() {
            // Use STANDARD.encode for both keys and values
            serializable_values.insert(STANDARD.encode(k), STANDARD.encode(v));
        }
        serde_json::to_string(&serializable_values).map_err(JsError::from)
    }

    pub fn deserialize(json_str: &str) -> Result<Self, JsError> {
        let serializable_values: HashMap<String, String> = serde_json::from_str(json_str)
            .map_err(JsError::from)?;
        let mut values = HashMap::new();
        for (k, v) in serializable_values {
            let key = STANDARD.decode(k.as_bytes()).map_err(JsError::from)?;
            let value = STANDARD.decode(v.as_bytes()).map_err(JsError::from)?;
            values.insert(key, value);
        }
        Ok(PersistentKeyStore {
            values: RwLock::new(values),
        })
    }
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum PersistentKeyStoreError {
    #[error("Error serializing value.")]
    SerializationError,
}
