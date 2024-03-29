use js_sys::Uint8Array;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{config::CryptoConfig, GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
    treesync::RatchetTreeIn,
    versions::ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use serde::{Serialize as SerdeSerialize, Deserialize as SerdeDeserialize};

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

    pub fn deserialize(serialized: &str, provider: &Provider) -> Result<Identity, JsError> {
        // Perform deserialization
        let identity: Identity = serde_json::from_str(serialized)
            .map_err(|e| JsError::new(&format!("Deserialization error: {}", e)))?;

        // Assuming Identity and KeyPair structures are adjusted to support serialization/deserialization properly
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
    proposal: Uint8Array,
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeAddMessages {
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[wasm_bindgen]
impl AddMessages {
    #[wasm_bindgen(getter)]
    pub fn proposal(&self) -> Uint8Array {
        self.proposal.clone()
    }
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

    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<AddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(&provider.0, &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_uint8array(&proposal_msg);
        let commit = mls_message_to_uint8array(&commit_msg);
        let welcome = mls_message_to_uint8array(&welcome_msg);

        Ok(AddMessages {
            proposal,
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
    fn native_propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: openmls::key_packages::KeyPackage,
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
pub struct KeyPackage(OpenMlsKeyPackage);

#[wasm_bindgen]
pub struct RatchetTree(RatchetTreeIn);

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
fn bytes_to_array_string(bytes: &Vec<u8>) -> String {
    let strings: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", strings.join(", "))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn js_error_to_string(e: JsError) -> String {
        let v: JsValue = e.into();
        // Assuming `log` is a function that can log to the console or elsewhere
        log(&format!("JsError as JsValue: {:?}", v));
        v.as_string().unwrap_or_else(|| "Unknown error occurred".to_string())
    }

    use wasm_bindgen_test::*;

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
            .native_propose_and_commit_add(&alice_provider, &alice, bob_key_pkg.0)
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

        let bob_key_pkg = bob.key_package(&bob_provider);
        let carol_key_pkg = carol.key_package(&carol_provider);

        let add_msgs_bob = chess_club_alice
            .native_propose_and_commit_add(&alice_provider, &alice, bob_key_pkg.0)
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
            .native_propose_and_commit_add(&alice_provider, &alice, carol_key_pkg.0)
            .map_err(js_error_to_string)
            .unwrap();

        log(&format!("welcome:  {}", bytes_to_array_string(&add_msgs_carol.welcome)));
        log(&format!("commit:   {}", bytes_to_array_string(&add_msgs_carol.commit)));


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

        match chess_club_bob.process_message(&bob_provider, &add_msgs_carol.commit) {
            Ok(_) => { log("Message processed successfully") }
            Err(e) => {
                let error_message = js_error_to_string(e);
                log(&format!("err:   {}", error_message));
                // Optionally, return or handle the error here instead of expecting
            }
        }
        chess_club_bob
            .merge_pending_commit(&alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let bob_exported_key = &chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key)
    }
}
