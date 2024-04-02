use js_sys::Uint8Array;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::convert::IntoWasmAbi;
use wasm_bindgen::prelude::*;

use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{config::CryptoConfig, GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
    treesync::RatchetTreeIn,
    versions::ProtocolVersion,
};
use openmls::prelude::{LeafNodeIndex as OpenMlsLeafNodeIndex, Member};
use openmls::prelude::OpenMlsKeyStore;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, types::Ciphersuite};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// The ciphersuite used here. Fixed in order to reduce the binary size.
static CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// The protocol version. We only support RFC MLS.
static VERSION: ProtocolVersion = ProtocolVersion::Mls10;

/// The config used in all calls that need a CryptoConfig, using hardcoded settings.
static CRYPTO_CONFIG: CryptoConfig = CryptoConfig {
    ciphersuite: CIPHERSUITE,
    version: VERSION,
};

#[wasm_bindgen]
pub struct LeafNodeIndex(OpenMlsLeafNodeIndex);

impl LeafNodeIndex {
    // Method to clone the inner OpenMlsKeyPackage
    pub fn clone_inner(&self) -> OpenMlsLeafNodeIndex {
        self.0.clone()
    }
    pub fn new(inner: OpenMlsLeafNodeIndex) -> LeafNodeIndex {
        LeafNodeIndex(inner)
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Provider(OpenMlsRustCrypto);

impl AsRef<OpenMlsRustCrypto> for Provider {
    fn as_ref(&self) -> &OpenMlsRustCrypto {
        &self.0
    }
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, openmls!");
}

#[wasm_bindgen]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct Identity {
    credential_with_key: CredentialWithKey,
    keypair: openmls_basic_credential::SignatureKeyPair,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, name: &str) -> Result<Identity, JsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity = name.bytes().collect();
        let credential = BasicCredential::new(identity)?;
        let keypair = SignatureKeyPair::new(signature_scheme)?;

        keypair.store(provider.0.key_store())?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair,
        })
    }

    pub fn key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage(
            OpenMlsKeyPackage::builder()
                .build(
                    CRYPTO_CONFIG,
                    &provider.0,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .unwrap(),
        )
    }
    pub fn serialize(&self) -> Result<String, JsError> {
        serde_json::to_string(self)
            .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
    }

    pub fn deserialize(provider: &Provider, serialized: &str) -> Result<Identity, JsError> {
        // Perform deserialization
        let identity: Identity = serde_json::from_str(serialized)
            .map_err(|e| JsError::new(&format!("Deserialization error: {}", e)))?;

        // Store the keypair back into the provider's key store after deserialization
        identity.keypair.store(provider.0.key_store())
            .map_err(|e| JsError::new(&format!("KeyPair storage error: {}", e)))?;

        Ok(identity)
    }
}

#[wasm_bindgen]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct Group {
    mls_group: MlsGroup,
}

#[wasm_bindgen]
pub struct AddMessages {
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[wasm_bindgen]
pub struct RemoveMessages {
    commit: Uint8Array,
    welcome: Option<Uint8Array>,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeAddMessages {
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[cfg(test)]
#[allow(dead_code)]
pub struct NativeRemoveMessages {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl AddMessages {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl RemoveMessages {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Option<Uint8Array> {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl Group {
    pub fn create_new(provider: &Provider, founder: &Identity, group_id: &str) -> Group {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();

        let mls_group = MlsGroup::builder()
            .crypto_config(CRYPTO_CONFIG)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .build(
                &provider.0,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();

        Group { mls_group }
    }
    pub fn join(
        provider: &Provider,
        mut welcome: &[u8],
        ratchet_tree: RatchetTree,
    ) -> Result<Group, JsError> {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            other => Err(openmls::error::ErrorString::from(format!(
                "expected a message of type welcome, got {other:?}",
            ))),
        }?;
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group =
            StagedWelcome::new_from_welcome(&provider.0, &config, welcome, Some(ratchet_tree.0))?
                .into_group(&provider.0)?;

        Ok(Group { mls_group })
    }

    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

    pub fn add_member(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<AddMessages, JsError> {
        let (mls_message_out, welcome, _group_info) = self
            .mls_group
            .add_members(provider.as_ref(), &sender.keypair, &[new_member.clone_inner()])?;

        let commit = mls_message_to_uint8array(&mls_message_out);
        let welcome = mls_message_to_uint8array(&welcome);

        Ok(AddMessages {
            commit,
            welcome,
        })
    }
    pub fn remove_member(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        removed_member: LeafNodeIndex,
    ) -> Result<RemoveMessages, JsError> {
        let (mls_message_out, welcome_option, _group_info) = self
            .mls_group
            .remove_members(provider.as_ref(), &sender.keypair, &[removed_member.clone_inner()])
            .map_err(|e| JsError::new(&format!("Failed to remove member: {}", e)))?;

        let commit = mls_message_to_uint8array(&mls_message_out);
        let welcome = welcome_option.map(|welcome_message| mls_message_to_uint8array(&welcome_message));

        Ok(RemoveMessages {
            commit,
            welcome,
        })
    }

    pub fn update_key_package(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> Result<RemoveMessages, JsError> {
        let (mls_message_out, welcome_option, _group_info) = self
            .mls_group
            .self_update(provider.as_ref(), &sender.keypair)
            .map_err(|e| JsError::new(&format!("Failed to update keypair: {}", e)))?;

        let commit = mls_message_to_uint8array(&mls_message_out);
        let welcome = welcome_option.map(|welcome_message| mls_message_to_uint8array(&welcome_message));

        Ok(RemoveMessages {
            commit,
            welcome,
        })
    }


    pub fn merge_pending_commit(&mut self, provider: &Provider) -> Result<(), JsError> {
        self.mls_group
            .merge_pending_commit(provider.as_ref())
            .map_err(|e| e.into())
    }

    pub fn process_message(
        &mut self,
        provider: &Provider,
        mut msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut msg).unwrap();

        let msg = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }

            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            openmls::framing::MlsMessageBodyIn::Welcome(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::GroupInfo(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::KeyPackage(_) => todo!(),
        };

        match msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(_)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Ok(vec![])
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_ref(), *staged_commit)?;
                Ok(vec![])
            }
        }
    }

    pub fn export_key(
        &self,
        provider: &Provider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .export_secret(provider.as_ref().crypto(), label, context, key_length)
            .map_err(|e| {
                println!("export key error: {e}");
                e.into()
            })
    }

    pub fn get_member_index(
        &self,
        member: &KeyPackage,
    ) -> Result<LeafNodeIndex, JsError> {
        let member_signature = member.0.leaf_node().signature_key().as_slice();

        let group_members = self.mls_group.members().collect::<Vec<Member>>();

        let member_match = group_members
            .iter()
            .find(|&member| {
                member.signature_key.as_slice() == member_signature
            });

        match member_match {
            Some(found_member) => Ok(LeafNodeIndex::new(found_member.index)),
            None => Err(JsError::new("Member not found.")),
        }
    }

    pub fn serialize(&self) -> Result<String, JsError> {
        serde_json::to_string(self)
            .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
    }

    pub fn deserialize(serialized: &str) -> Result<Group, JsError> {
        serde_json::from_str(serialized)
            .map_err(|e| JsError::new(&format!("Deserialization error: {}", e)))
    }
}

#[cfg(test)]
impl Group {
    fn native_add_member(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: OpenMlsKeyPackage,
    ) -> Result<NativeAddMessages, JsError> {
        let (mls_message_out, welcome, _group_info) = self
            .mls_group
            .add_members(provider.as_ref(), &sender.keypair, &[new_member])?;

        let commit = mls_message_to_u8vec(&mls_message_out);
        let welcome = mls_message_to_u8vec(&welcome);

        Ok(NativeAddMessages {
            commit,
            welcome,
        })
    }

    fn native_join(provider: &Provider, mut welcome: &[u8], ratchet_tree: RatchetTree) -> Group {
        let welcome = MlsMessageIn::tls_deserialize(&mut welcome)
            .unwrap()
            .into_welcome()
            .expect("expected a message of type welcome");
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group = StagedWelcome::new_from_welcome(
            provider.as_ref(),
            &config,
            welcome,
            Some(ratchet_tree.0),
        )
            .unwrap()
            .into_group(provider.as_ref())
            .unwrap();

        Group { mls_group }
    }

    pub fn native_remove_member(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        removed_member: OpenMlsLeafNodeIndex,
    ) -> Result<NativeRemoveMessages, JsError> {
        let (mls_message_out, welcome_option, _group_info) = self
            .mls_group
            .remove_members(provider.as_ref(), &sender.keypair, &[removed_member])
            .map_err(|e| JsError::new(&format!("Failed to remove member: {}", e)))?;

        let commit = mls_message_to_u8vec(&mls_message_out);
        let welcome = welcome_option.map(|welcome_message| mls_message_to_u8vec(&welcome_message));

        Ok(NativeRemoveMessages {
            commit,
            welcome,
        })
    }
    pub fn native_update_key_package(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> Result<NativeRemoveMessages, JsError> {
        let (mls_message_out, welcome_option, _group_info) = self
            .mls_group
            .self_update(provider.as_ref(), &sender.keypair)
            .map_err(|e| JsError::new(&format!("Failed to update keypair: {}", e)))?;

        let commit = mls_message_to_u8vec(&mls_message_out);
        let welcome = welcome_option.map(|welcome_message| mls_message_to_u8vec(&welcome_message));

        Ok(NativeRemoveMessages {
            commit,
            welcome,
        })
    }

    pub fn native_get_member_index(
        &self,
        member: &KeyPackage,
    ) -> Result<OpenMlsLeafNodeIndex, JsError> {
        let member_signature = member.0.leaf_node().signature_key().as_slice();

        let group_members = self.mls_group.members().collect::<Vec<Member>>();

        let member_match = group_members
            .iter()
            .find(|&member| {
                member.signature_key.as_slice() == member_signature
            });

        match member_match {
            Some(found_member) => Ok(found_member.index),
            None => Err(JsError::new("Member not found.")),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct NoWelcomeError;

impl std::fmt::Display for NoWelcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no welcome")
    }
}

impl std::error::Error for NoWelcomeError {}

#[wasm_bindgen]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct KeyPackage(OpenMlsKeyPackage);

#[wasm_bindgen]
impl KeyPackage {
    pub fn serialize(&self) -> Result<String, JsError> {
        serde_json::to_string(self)
            .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
    }

    pub fn deserialize(serialized: &str) -> Result<KeyPackage, JsError> {
        serde_json::from_str(serialized)
            .map_err(|e| JsError::new(&format!("Deserialization error: {}", e)))
    }
}

impl KeyPackage {
    // Method to clone the inner OpenMlsKeyPackage
    pub fn clone_inner(&self) -> OpenMlsKeyPackage {
        self.0.clone()
    }
}

#[wasm_bindgen]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct RatchetTree(RatchetTreeIn);

#[wasm_bindgen]
impl RatchetTree {
    pub fn serialize(&self) -> Result<String, JsError> {
        serde_json::to_string(self)
            .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
    }

    pub fn deserialize(serialized: &str) -> Result<RatchetTree, JsError> {
        serde_json::from_str(serialized)
            .map_err(|e| JsError::new(&format!("Deserialization error: {}", e)))
    }
}

fn mls_message_to_uint8array(msg: &MlsMessageOut) -> Uint8Array {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();

    unsafe { Uint8Array::new(&Uint8Array::view(&serialized)) }
}

#[cfg(test)]
fn mls_message_to_u8vec(msg: &MlsMessageOut) -> Vec<u8> {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    serialized
}


#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    fn js_error_to_string(e: JsError) -> String {
        let v: JsValue = e.into();
        // Assuming `log` is a function that can log to the console or elsewhere
        log(&format!("JsError as JsValue: {:?}", v));
        v.as_string().unwrap_or_else(|| "Unknown error occurred".to_string())
    }

    #[cfg(test)]
    fn bytes_to_array_string_vec(bytes: &Vec<u8>) -> String {
        let strings: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
        format!("[{}]", strings.join(", "))
    }

    // #[cfg(test)]
    // fn bytes_to_array_string_u8(bytes: &[u8]) -> String {
    //     let strings: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    //     format!("[{}]", strings.join(", "))
    // }

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn basic() {
        let alice_provider = Provider::new();
        let bob_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice")
            .map_err(js_error_to_string)
            .unwrap();
        let bob = Identity::new(&bob_provider, "bob")
            .map_err(js_error_to_string)
            .unwrap();

        let mut chess_club_alice = Group::create_new(&alice_provider, &alice, "chess club");

        let bob_key_pkg = bob.key_package(&bob_provider);

        let add_msgs = chess_club_alice
            .native_add_member(&alice_provider, &alice, bob_key_pkg.0)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();

        let chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        let bob_exported_key = chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let alice_exported_key = chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key)
    }

    #[wasm_bindgen_test]
    fn three_users() {
        let alice_provider = Provider::new();
        let bob_provider = Provider::new();
        let carol_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice")
            .map_err(js_error_to_string)
            .unwrap();
        let bob = Identity::new(&bob_provider, "bob")
            .map_err(js_error_to_string)
            .unwrap();
        let carol = Identity::new(&carol_provider, "carol")
            .map_err(js_error_to_string)
            .unwrap();


        let mut chess_club_alice = Group::create_new(&alice_provider, &alice, "chess club");

        let alice_key_pkg = alice.key_package(&alice_provider);
        let bob_key_pkg = bob.key_package(&bob_provider);
        let carol_key_pkg = carol.key_package(&carol_provider);

        let serialized_carol_key_pkg = carol_key_pkg.serialize()
            .map_err(js_error_to_string)
            .unwrap();

        let deserialized_key_pkg = KeyPackage::deserialize(&serialized_carol_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        let add_msgs_bob = chess_club_alice
            .native_add_member(&alice_provider, &alice, bob_key_pkg.0.clone())
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();

        let mut chess_club_bob = Group::native_join(&bob_provider, &add_msgs_bob.welcome, ratchet_tree);

        let alice_exported_key = chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let bob_exported_key = chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key);

        let add_msgs_carol = chess_club_alice
            .native_add_member(&alice_provider, &alice, carol_key_pkg.0)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();

        let mut chess_club_carol = Group::native_join(&carol_provider, &add_msgs_carol.welcome, ratchet_tree);

        let alice_exported_key = &chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let bob_exported_key = &chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let carol_exported_key = &chess_club_carol
            .export_key(&carol_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_ne!(bob_exported_key, alice_exported_key);
        assert_eq!(carol_exported_key, alice_exported_key);

        chess_club_bob.process_message(&bob_provider, &add_msgs_carol.commit)
            .map_err(js_error_to_string)
            .unwrap();


        let bob_exported_key = &chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key);

        log(&format!("alice key:    {}", bytes_to_array_string_vec(alice_exported_key)));
        log(&format!("bob key:      {}", bytes_to_array_string_vec(bob_exported_key)));
        log(&format!("carol key:    {}", bytes_to_array_string_vec(carol_exported_key)));

        let alice_index = chess_club_bob.native_get_member_index(&alice_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        // let bob_index = bob_member.index;
        // log(&format!("bob index:    {}", bob_index));

        let remove_msg_alice = chess_club_bob
            .native_remove_member(&bob_provider, &bob, alice_index)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_bob
            .merge_pending_commit(&alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_carol.process_message(&carol_provider, &remove_msg_alice.commit)
            .map_err(js_error_to_string)
            .unwrap();

        let alice_exported_key = &chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let bob_exported_key = &chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let carol_exported_key = &chess_club_carol
            .export_key(&carol_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        log(&format!("alice key:    {}", bytes_to_array_string_vec(alice_exported_key)));
        log(&format!("bob key:      {}", bytes_to_array_string_vec(bob_exported_key)));
        log(&format!("carol key:    {}", bytes_to_array_string_vec(carol_exported_key)));

        assert_ne!(bob_exported_key, alice_exported_key);
        assert_eq!(carol_exported_key, bob_exported_key);

        let update_bob_key_msg = chess_club_bob
            .native_update_key_package(&bob_provider, &bob)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_bob
            .merge_pending_commit(&alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_carol.process_message(&carol_provider, &update_bob_key_msg.commit)
            .map_err(js_error_to_string)
            .unwrap();

        let bob_exported_key = &chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let carol_exported_key = &chess_club_carol
            .export_key(&carol_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        log(&format!("alice key:    {}", bytes_to_array_string_vec(alice_exported_key)));
        log(&format!("bob key:      {}", bytes_to_array_string_vec(bob_exported_key)));
        log(&format!("carol key:    {}", bytes_to_array_string_vec(carol_exported_key)));

        assert_eq!(carol_exported_key, bob_exported_key);
    }
}
