// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::ciphersuite::*;
use crate::codec::*;
use crate::creds::*;
use crate::key_packages::*;
use crate::messages::{proposals::*, *};

// Tree modules
pub(crate) mod codec;
pub(crate) mod hash_input;
pub(crate) mod index;
pub(crate) mod node;
pub(crate) mod path_keys;
pub(crate) mod private_tree;
pub(crate) mod secret_tree;
pub(crate) mod sender_ratchet;
pub(crate) mod treemath;

use hash_input::*;
use index::*;
use node::*;
use path_keys::PathKeys;
use private_tree::{PathSecrets, PrivateTree};

// Internal tree tests
#[cfg(test)]
mod test_path_keys;
#[cfg(test)]
mod test_private_tree;
#[cfg(test)]
mod test_secret_tree;
#[cfg(test)]
mod test_treemath;
#[cfg(test)]
mod test_util;

#[derive(Debug)]
/// The ratchet tree.
pub struct RatchetTree {
    /// The ciphersuite used in this tree.
    ciphersuite: Ciphersuite,

    /// All nodes in the tree.
    /// Note that these only hold public values.
    /// Private values are stored in the `private_tree`.
    pub nodes: Vec<Node>,

    /// This holds all private values in the tree.
    /// See `PrivateTree` for details.
    private_tree: PrivateTree,
}

impl RatchetTree {
    /// Create a new empty `RatchetTree`.
    pub(crate) fn new(ciphersuite_name: CiphersuiteName, kpb: KeyPackageBundle) -> RatchetTree {
        let nodes = vec![Node {
            node_type: NodeType::Leaf,
            key_package: Some(kpb.get_key_package().clone()),
            node: None,
        }];
        let private_tree = PrivateTree::new(
            kpb.private_key,
            NodeIndex::from(0u32),
            PathKeys::default(),
            CommitSecret(Vec::new()),
            Vec::new(),
        );

        RatchetTree {
            ciphersuite: Ciphersuite::new(ciphersuite_name),
            nodes,
            private_tree,
        }
    }

    /// Generate a new `RatchetTree` from `Node`s with the client's key package
    /// bundle `kpb`.
    pub(crate) fn new_from_nodes(
        ciphersuite_name: CiphersuiteName,
        kpb: KeyPackageBundle,
        node_options: &[Option<Node>],
    ) -> Result<RatchetTree, TreeError> {
        fn find_kp_in_tree(
            key_package: &KeyPackage,
            nodes: &[Option<Node>],
        ) -> Result<NodeIndex, TreeError> {
            for (i, node_option) in nodes.iter().enumerate() {
                if let Some(node) = node_option {
                    if let Some(kp) = &node.key_package {
                        if kp == key_package {
                            return Ok(NodeIndex::from(i));
                        }
                    }
                }
            }
            Err(TreeError::InvalidArguments)
        }

        // Find the own node in the list of nodes.
        let own_node_index = find_kp_in_tree(kpb.get_key_package(), node_options)?;

        // Build a full set of nodes for the tree based on the potentially incomplete
        // input nodes.
        let mut nodes = Vec::with_capacity(node_options.len());
        for (i, node_option) in node_options.iter().enumerate() {
            if let Some(node) = node_option.clone() {
                nodes.push(node);
            } else if i % 2 == 0 {
                nodes.push(Node::new_leaf(None));
            } else {
                nodes.push(Node::new_blank_parent_node());
            }
        }

        let ciphersuite = Ciphersuite::new(ciphersuite_name);
        // Build private tree
        let direct_path =
            treemath::direct_path_root(own_node_index, NodeIndex::from(nodes.len()).into())
                .expect("new_from_nodes: TreeMath error when computing direct path.");
        let (private_tree, public_keys) =
            PrivateTree::new_raw(&ciphersuite, own_node_index, kpb.private_key, &direct_path)?;

        // Build tree.
        let mut out = RatchetTree {
            ciphersuite,
            nodes,
            private_tree,
        };

        // Merge public keys into the tree.
        out.merge_direct_path(&direct_path, public_keys)?;

        Ok(out)
    }

    /// Return a mutable reference to the `PrivateTree`.
    pub(crate) fn get_private_tree_mut(&mut self) -> &mut PrivateTree {
        &mut self.private_tree
    }

    fn tree_size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    pub(crate) fn public_key_tree(&self) -> Vec<Option<Node>> {
        let mut tree = vec![];
        for node in self.nodes.iter() {
            if node.is_blank() {
                tree.push(None)
            } else {
                tree.push(Some(node.clone()))
            }
        }
        tree
    }

    pub(crate) fn leaf_count(&self) -> LeafIndex {
        self.tree_size().into()
    }

    fn resolve(&self, index: NodeIndex) -> Vec<NodeIndex> {
        let size = self.leaf_count();

        if self.nodes[index.as_usize()].node_type == NodeType::Leaf {
            if self.nodes[index.as_usize()].is_blank() {
                return vec![];
            } else {
                return vec![index];
            }
        }

        if !self.nodes[index.as_usize()].is_blank() {
            let mut unmerged_leaves = vec![index];
            let node = &self.nodes[index.as_usize()].node.as_ref();
            unmerged_leaves.extend(
                node.unwrap()
                    .get_unmerged_leaves()
                    .iter()
                    .map(|n| NodeIndex::from(*n)),
            );
            return unmerged_leaves;
        }

        let mut left = self.resolve(
            treemath::left(index).expect("resolve: TreeMath error when computing left child."),
        );
        let right = self.resolve(
            treemath::right(index, size)
                .expect("resolve: TreeMath error when computing right child."),
        );
        left.extend(right);
        left
    }

    // fn get_path_keypairs(&self) -> &PathKeypairs {
    //     &self.path_keypairs
    // }

    // pub(crate) fn set_path_keypairs(&mut self, path_keypairs: PathKeypairs) {
    //     self.path_keypairs = path_keypairs;
    // }

    /// Get the index of the own node.
    pub(crate) fn get_own_node_index(&self) -> NodeIndex {
        self.private_tree.get_node_index()
    }

    /// Get a reference to the own key package.
    fn get_own_key_package_ref(&self) -> &KeyPackage {
        let own_node = &self.nodes[self.get_own_node_index().as_usize()];
        own_node.key_package.as_ref().unwrap()
    }

    /// Get a mutable reference to the own key package.
    fn get_own_key_package_ref_mut(&mut self) -> &mut KeyPackage {
        let own_node = self
            .nodes
            .get_mut(self.private_tree.get_node_index().as_usize())
            .unwrap();
        own_node.get_key_package_ref_mut().unwrap()
    }

    // fn get_own_private_key(&self) -> &HPKEPrivateKey {
    //     &self.own_private_key
    // }

    fn blank_member(&mut self, index: NodeIndex) {
        let size = self.leaf_count();
        self.nodes[index.as_usize()].blank();
        self.nodes[treemath::root(size).as_usize()].blank();
        for index in treemath::dirpath(index, size)
            .expect("blank_member: TreeMath error when computing direct path.")
        {
            self.nodes[index.as_usize()].blank();
        }
    }
    fn free_leaves(&self) -> Vec<NodeIndex> {
        let mut free_leaves = vec![];
        for i in 0..self.leaf_count().as_usize() {
            // TODO use an iterator instead
            let leaf_index = LeafIndex::from(i);
            if self.nodes[NodeIndex::from(leaf_index).as_usize()].is_blank() {
                free_leaves.push(NodeIndex::from(i));
            }
        }
        free_leaves
    }

    /// 7.7. Update Paths
    ///
    /// Update the path for incoming commits.
    ///
    /// > The path contains a public key and encrypted secret value for all
    /// > intermediate nodes in the path above the leaf. The path is ordered
    /// > from the closest node to the leaf to the root; each node MUST be the
    /// > parent of its predecessor.
    ///
    pub(crate) fn update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &UpdatePath,
        group_context: &[u8],
    ) -> Result<CommitSecret, TreeError> {
        let own_index = self.get_own_node_index();

        // Find common ancestor of own leaf and sender leaf
        let common_ancestor_index =
            treemath::common_ancestor_index(NodeIndex::from(sender), own_index);

        // Calculate sender direct path & co-path, common path
        let sender_direct_path =
            treemath::direct_path_root(NodeIndex::from(sender), self.leaf_count())
                .expect("update_path: Error when computing direct path.");
        let sender_co_path = treemath::copath(NodeIndex::from(sender), self.leaf_count())
            .expect("update_path: Error when computing copath.");

        // Find the position of the common ancestor in the sender's direct path
        let common_ancestor_sender_dirpath_index = sender_direct_path
            .iter()
            .position(|&x| x == common_ancestor_index)
            .unwrap();
        let common_ancestor_copath_index =
            match sender_co_path.get(common_ancestor_sender_dirpath_index) {
                Some(i) => *i,
                None => return Err(TreeError::InvalidArguments),
            };

        // Resolve the node of that co-path index
        let resolution = self.resolve(common_ancestor_copath_index);
        let position_in_resolution = resolution.iter().position(|&x| x == own_index).unwrap_or(0);

        // Decrypt the ciphertext of that node
        let common_ancestor_node = match update_path.nodes.get(common_ancestor_sender_dirpath_index)
        {
            Some(node) => node,
            None => return Err(TreeError::InvalidArguments),
        };
        debug_assert_eq!(
            resolution.len(),
            common_ancestor_node.encrypted_path_secret.len()
        );
        if resolution.len() != common_ancestor_node.encrypted_path_secret.len() {
            return Err(TreeError::InvalidUpdatePath);
        }
        let hpke_ciphertext = &common_ancestor_node.encrypted_path_secret[position_in_resolution];

        // Get the HPKE private key.
        // It's either the own key or must be in the path of the private tree.
        let private_key = if resolution[position_in_resolution] == own_index {
            self.private_tree.get_hpke_private_key()
        } else {
            match self
                .private_tree
                .get_path_keys()
                .get(common_ancestor_copath_index)
            {
                Some(k) => k,
                None => return Err(TreeError::InvalidArguments),
            }
        };

        // Compute the common path between the common ancestor and the root
        let common_path = treemath::dirpath_long(common_ancestor_index, self.leaf_count())
            .expect("update_path: Error when computing direct path.");

        debug_assert!(sender_direct_path.len() > common_path.len());
        if sender_direct_path.len() <= common_path.len() {
            return Err(TreeError::InvalidArguments);
        }
        let sender_path_offset = sender_direct_path.len() - common_path.len();

        // Decrypt the secret and derive path secrets
        let secret = self
            .ciphersuite
            .hpke_open(hpke_ciphertext, &private_key, group_context, &[]);
        self.private_tree.generate_path_secrets(
            &self.ciphersuite,
            Some(&secret),
            common_path.len(),
        );
        self.private_tree
            .generate_commit_secret(&self.ciphersuite)?;

        // Update path key pairs for the new path secrets generated above.
        let new_path_public_keys = self
            .private_tree
            .generate_path_keypairs(&self.ciphersuite, &common_path)?;

        // Check that the public keys are consistent with the update path.
        for (i, key) in new_path_public_keys
            .iter()
            .enumerate()
            .take(common_path.len())
        {
            debug_assert_eq!(&update_path.nodes[sender_path_offset + i].public_key, key);
            if &update_path.nodes[sender_path_offset + i].public_key != key {
                return Err(TreeError::InvalidUpdatePath);
            }
        }

        // Merge new nodes into the tree
        self.merge_direct_path_keys(update_path, sender_direct_path)?;
        self.merge_public_keys(&new_path_public_keys, &common_path)?;
        self.nodes[NodeIndex::from(sender).as_usize()] =
            Node::new_leaf(Some(update_path.leaf_key_package.clone()));
        self.compute_parent_hash(NodeIndex::from(sender));

        // TODO: Do we really want to return the commit secret here?
        Ok(self.private_tree.get_commit_secret())
    }

    /// Update the private tree with the new `KeyPackageBundle`.
    pub(crate) fn replace_private_tree(
        &mut self,
        key_package_bundle: KeyPackageBundle,
        group_context: &[u8],
    ) -> Result<CommitSecret, TreeError> {
        let _path_option = self.replace_private_tree_(
            key_package_bundle,
            group_context,
            false, /* without update path */
        )?;
        Ok(self.private_tree.get_commit_secret())
    }

    /// Update the private tree.
    pub(crate) fn refresh_private_tree(
        &mut self,
        signature_key: &SignaturePrivateKey,
        group_context: &[u8],
    ) -> Result<(CommitSecret, Option<UpdatePath>, Option<PathSecrets>), TreeError> {
        // Generate new keypair
        let own_index = self.get_own_node_index();
        let (private_key, public_key) = self.ciphersuite.new_hpke_keypair().into_keys();

        // Replace the init key in the current KeyPackage
        let key_package_bundle = {
            // Generate new keypair and replace it in current KeyPackage
            let mut key_package = self.get_own_key_package_ref().clone();
            key_package.set_hpke_init_key(public_key);
            KeyPackageBundle::from_values(key_package, private_key)
        };

        // Replace the private tree with a new ine based on the new key package
        // bundle and store the key package in the own node.
        let path_option = self.replace_private_tree_(
            key_package_bundle,
            group_context,
            true, /* with update path */
        )?;

        // Compute the parent hash extension and update the KeyPackage
        let csuite = self.ciphersuite;
        let parent_hash = self.compute_parent_hash(own_index);
        let key_package = self.get_own_key_package_ref_mut();
        key_package.update_parent_hash(&parent_hash);
        key_package.sign(&csuite, signature_key);

        Ok((
            self.private_tree.get_commit_secret(),
            path_option,
            Some(self.private_tree.get_path_secrets().to_vec()),
        ))
    }

    /// Replace the private tree with a new one based on the `key_package_bundle`.
    fn replace_private_tree_(
        &mut self,
        key_package_bundle: KeyPackageBundle,
        group_context: &[u8],
        with_update_path: bool,
    ) -> Result<Option<UpdatePath>, TreeError> {
        let (private_key, key_package) = key_package_bundle.into_tuple();
        // Compute the direct path and keypairs along it
        let own_index = self.get_own_node_index();
        let direct_path_root = treemath::direct_path_root(own_index, self.leaf_count())
            .expect("replace_private_tree: Error when computing direct path.");

        // Update private tree and merge corresponding public keys.
        let new_public_keys =
            self.private_tree
                .update(&self.ciphersuite, Some(private_key), &direct_path_root)?;
        self.merge_public_keys(&new_public_keys, &direct_path_root)?;

        // Update own leaf node with the new values
        self.nodes[own_index.as_usize()] = Node::new_leaf(Some(key_package.clone()));

        if !with_update_path {
            return Ok(None);
        }

        let update_path_nodes = self.encrypt_to_copath(new_public_keys, group_context)?;
        let update_path = UpdatePath::new(key_package, update_path_nodes);
        Ok(Some(update_path))
    }

    /// Encrypt the path secrets to the co path and return the update path.
    fn encrypt_to_copath(
        &self,
        public_keys: Vec<HPKEPublicKey>,
        group_context: &[u8],
    ) -> Result<Vec<UpdatePathNode>, TreeError> {
        let copath = treemath::copath(self.private_tree.get_node_index(), self.leaf_count())
            .expect("encrypt_to_copath: Error when computing copath.");
        let path_secrets = self.private_tree.get_path_secrets();

        debug_assert_eq!(path_secrets.len(), copath.len());
        if path_secrets.len() != copath.len() {
            return Err(TreeError::InvalidArguments);
        }
        debug_assert_eq!(public_keys.len(), copath.len());
        if public_keys.len() != copath.len() {
            return Err(TreeError::InvalidArguments);
        }

        let mut direct_path_nodes = vec![];
        let mut ciphertexts = vec![];
        for (path_secret, copath_node) in path_secrets.iter().zip(copath.iter()) {
            let node_ciphertexts: Vec<HpkeCiphertext> = self
                .resolve(*copath_node)
                .iter()
                .map(|&x| {
                    let pk = self.nodes[x.as_usize()].get_public_hpke_key().unwrap();
                    self.ciphersuite
                        .hpke_seal(&pk, group_context, &[], &path_secret)
                })
                .collect();
            // TODO Check that all public keys are non-empty
            // TODO Handle potential errors
            ciphertexts.push(node_ciphertexts);
        }
        for (public_key, node_ciphertexts) in public_keys.iter().zip(ciphertexts.iter()) {
            direct_path_nodes.push(UpdatePathNode {
                // TODO: don't clone ...
                public_key: public_key.clone(),
                encrypted_path_secret: node_ciphertexts.clone(),
            });
        }
        Ok(direct_path_nodes)
    }

    /// Merge public keys from a direct path to this tree along the given path.
    fn merge_direct_path_keys(
        &mut self,
        direct_path: &UpdatePath,
        path: Vec<NodeIndex>,
    ) -> Result<(), TreeError> {
        debug_assert_eq!(direct_path.nodes.len(), path.len());
        if direct_path.nodes.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }

        for (i, p) in path.iter().enumerate() {
            let public_key = direct_path.nodes[i].clone().public_key;
            let node = ParentNode::new(public_key.clone(), &[], &[]);
            self.nodes[p.as_usize()].node = Some(node);
        }

        Ok(())
    }

    /// Merge public keys along the direct path of the own node.
    fn merge_direct_path(
        &mut self,
        direct_path: &[NodeIndex],
        keys: Vec<HPKEPublicKey>,
    ) -> Result<(), TreeError> {
        debug_assert_eq!(direct_path.len(), keys.len());
        if direct_path.len() != keys.len() {
            return Err(TreeError::InvalidArguments);
        }

        for (key, path_index) in keys.iter().zip(direct_path) {
            // TODO: this is pretty ugly
            let node = match self.nodes.get(path_index.as_usize()) {
                Some(node) => node.node.clone().unwrap(),
                None => ParentNode::new(key.clone(), &[], &[]),
            };
            self.nodes[path_index.as_usize()].node = Some(node);
        }

        Ok(())
    }

    /// Merges `public_keys` into the tree along the `path`
    pub(crate) fn merge_public_keys(
        &mut self,
        public_keys: &[HPKEPublicKey],
        path: &[NodeIndex],
    ) -> Result<(), TreeError> {
        debug_assert_eq!(public_keys.len(), path.len());
        if public_keys.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }
        for i in 0..path.len() {
            // TODO: drop clone
            let node = ParentNode::new(public_keys[i].clone(), &[], &[]);
            self.nodes[path[i].as_usize()].node = Some(node);
        }
        Ok(())
    }

    /// Add nodes for the provided key packages.
    pub(crate) fn add_nodes(&mut self, new_kps: &[&KeyPackage]) -> Vec<(NodeIndex, Credential)> {
        let num_new_kp = new_kps.len();
        let mut added_members = Vec::with_capacity(num_new_kp);

        if num_new_kp > (2 * self.leaf_count().as_usize()) {
            self.nodes
                .reserve_exact((2 * num_new_kp) - (2 * self.leaf_count().as_usize()));
        }

        // Add new nodes for key packages into existing free leaves.
        // Note that zip makes it so only the first free_leaves().len() nodes are taken.
        let free_leaves = self.free_leaves();
        let free_leaves_len = free_leaves.len();
        for (new_kp, leaf_index) in new_kps.iter().zip(free_leaves) {
            self.nodes[leaf_index.as_usize()] = Node::new_leaf(Some((*new_kp).clone()));
            let dirpath = treemath::direct_path_root(leaf_index, self.leaf_count())
                .expect("add_nodes: Error when computing direct path.");
            for d in dirpath.iter() {
                if !self.nodes[d.as_usize()].is_blank() {
                    let node = &self.nodes[d.as_usize()];
                    let index = d.as_u32();
                    // TODO handle error
                    let mut parent_node = node.node.clone().unwrap();
                    if !parent_node.get_unmerged_leaves().contains(&index) {
                        parent_node.get_unmerged_leaves_mut().push(index);
                    }
                    self.nodes[d.as_usize()].node = Some(parent_node);
                }
            }
            added_members.push((leaf_index, new_kp.get_credential().clone()));
        }
        // Add the remaining nodes.
        let mut new_nodes = Vec::with_capacity(num_new_kp * 2);
        let mut leaf_index = self.nodes.len() + 1;
        for add_proposal in new_kps.iter().skip(free_leaves_len) {
            new_nodes.extend(vec![
                Node::new_blank_parent_node(),
                Node::new_leaf(Some((*add_proposal).clone())),
            ]);
            let node_index = NodeIndex::from(leaf_index);
            added_members.push((node_index, add_proposal.get_credential().clone()));
            leaf_index += 2;
        }
        self.nodes.extend(new_nodes);
        self.trim_tree();
        added_members
    }

    /// Applies a list of proposals from a Commit to the tree.
    /// `proposal_id_list` corresponds to the `proposals` field of a Commit
    /// `proposal_queue` is the queue of proposals received or sent in the current epoch
    /// `updates_key_package_bundles` is the list of own KeyPackageBundles corresponding to updates or commits sent in the current epoch
    pub fn apply_proposals(
        &mut self,
        proposal_id_list: &[ProposalID],
        proposal_queue: ProposalQueue,
        updates_key_package_bundles: &mut Vec<KeyPackageBundle>,
        // (path_required, self_removed, invitation_list)
    ) -> Result<(bool, bool, InvitationList), TreeError> {
        let mut has_updates = false;
        let mut has_removes = false;
        let mut invitation_list = Vec::new();

        let mut self_removed = false;

        // Process updates first
        for queued_proposal in proposal_queue
            .get_filtered_proposals(proposal_id_list, ProposalType::Update)
            .iter()
        {
            has_updates = true;
            let update_proposal = &queued_proposal.get_proposal_ref().as_update().unwrap();
            let sender_index = queued_proposal.get_sender_ref().as_node_index();
            // Prepare leaf node
            let leaf_node = Node::new_leaf(Some(update_proposal.key_package.clone()));
            // Blank the direct path of that leaf node
            self.blank_member(sender_index);
            // Replace the leaf node
            self.nodes[sender_index.as_usize()] = leaf_node;
            // Check if it is a self-update
            if sender_index == self.get_own_node_index() {
                let own_kpb_index = match updates_key_package_bundles
                    .iter()
                    .position(|kpb| kpb.get_key_package() == &update_proposal.key_package)
                {
                    Some(i) => i,
                    // We lost the KeyPackageBundle apparently
                    None => return Err(TreeError::InvalidArguments),
                };
                // Get and remove own KeyPackageBundle from the list of available ones
                let own_kpb = updates_key_package_bundles.remove(own_kpb_index);
                // Update the private tree with new values
                self.private_tree = PrivateTree::new(
                    own_kpb.private_key,
                    sender_index,
                    PathKeys::default(),
                    CommitSecret(Vec::new()),
                    Vec::new(),
                );
            }
        }
        for queued_proposal in proposal_queue
            .get_filtered_proposals(proposal_id_list, ProposalType::Remove)
            .iter()
        {
            has_removes = true;
            let remove_proposal = &queued_proposal.get_proposal_ref().as_remove().unwrap();
            let removed = NodeIndex::from(remove_proposal.removed);
            // Check if we got removed from the group
            if removed == self.get_own_node_index() {
                self_removed = true;
            }
            // Blank the direct path of the removed member
            self.blank_member(removed);
        }

        // Process adds
        let add_proposals: Vec<AddProposal> = proposal_queue
            .get_filtered_proposals(proposal_id_list, ProposalType::Add)
            .iter()
            .map(|queued_proposal| {
                let proposal = &queued_proposal.get_proposal_ref();
                proposal.as_add().unwrap()
            })
            .collect();
        let has_adds = !add_proposals.is_empty();
        // Extract KeyPackages from proposals
        let key_packages: Vec<&KeyPackage> = add_proposals.iter().map(|a| &a.key_package).collect();
        // Add new members to tree
        let added_members = self.add_nodes(&key_packages);

        // Prepare invitations
        for (i, added) in added_members.iter().enumerate() {
            invitation_list.push((added.0, add_proposals.get(i).unwrap().clone()));
        }

        // Determine if Commit needs a path field
        let path_required = has_updates || has_removes || !has_adds;

        Ok((path_required, self_removed, invitation_list))
    }
    /// Trims the tree from the right when there are empty leaf nodes
    fn trim_tree(&mut self) {
        let mut new_tree_size = 0;

        for i in 0..self.nodes.len() {
            if !self.nodes[i].is_blank() {
                new_tree_size = i + 1;
            }
        }

        if new_tree_size > 0 {
            self.nodes.truncate(new_tree_size);
        }
    }
    /// Computes the tree hash
    pub fn compute_tree_hash(&self) -> Vec<u8> {
        fn node_hash(ciphersuite: &Ciphersuite, tree: &RatchetTree, index: NodeIndex) -> Vec<u8> {
            let node = &tree.nodes[index.as_usize()];
            match node.node_type {
                NodeType::Leaf => {
                    let leaf_node_hash = LeafNodeHashInput::new(&index, &node.key_package);
                    leaf_node_hash.hash(ciphersuite)
                }
                NodeType::Parent => {
                    let left = treemath::left(index)
                        .expect("node_hash: Error when computing left child of node.");
                    let left_hash = node_hash(ciphersuite, tree, left);
                    let right = treemath::right(index, tree.leaf_count())
                        .expect("node_hash: Error when computing left child of node.");
                    let right_hash = node_hash(ciphersuite, tree, right);
                    let parent_node_hash = ParentNodeHashInput::new(
                        index.as_u32(),
                        &node.node,
                        &left_hash,
                        &right_hash,
                    );
                    parent_node_hash.hash(ciphersuite)
                }
                NodeType::Default => panic!("Default node type not supported in tree hash."),
            }
        }
        let root = treemath::root(self.leaf_count());
        node_hash(&self.ciphersuite, &self, root)
    }
    /// Computes the parent hash
    pub fn compute_parent_hash(&mut self, index: NodeIndex) -> Vec<u8> {
        let parent = treemath::parent(index, self.leaf_count())
            .expect("compute_parent_hash: Error when computing node parent.");
        let parent_hash = if parent == treemath::root(self.leaf_count()) {
            let root_node = &self.nodes[parent.as_usize()];
            root_node.hash(&self.ciphersuite).unwrap()
        } else {
            self.compute_parent_hash(parent)
        };
        let current_node = &self.nodes[index.as_usize()];
        if let Some(mut parent_node) = current_node.node.clone() {
            parent_node.set_parent_hash(parent_hash);
            self.nodes[index.as_usize()].node = Some(parent_node);
            let updated_parent_node = &self.nodes[index.as_usize()];
            updated_parent_node.hash(&self.ciphersuite).unwrap()
        } else {
            parent_hash
        }
    }
    /// Verifies the integrity of a public tree
    pub fn verify_integrity(ciphersuite: &Ciphersuite, nodes: &[Option<Node>]) -> bool {
        let node_count = NodeIndex::from(nodes.len());
        let size = node_count;
        for i in 0..node_count.as_usize() {
            let node_option = &nodes[i];
            if let Some(node) = node_option {
                match node.node_type {
                    NodeType::Parent => {
                        let left_index = treemath::left(NodeIndex::from(i))
                            .expect("verify_integrity: Error when computing left child of node.");
                        let right_index = treemath::right(NodeIndex::from(i), size.into())
                            .expect("verify_integrity: Error when computing right child of node.");
                        if right_index >= node_count {
                            return false;
                        }
                        let left_option = &nodes[left_index.as_usize()];
                        let right_option = &nodes[right_index.as_usize()];
                        let own_hash = node.hash(ciphersuite).unwrap();
                        if let Some(right) = right_option {
                            if let Some(left) = left_option {
                                let left_parent_hash = left.parent_hash().unwrap_or_else(Vec::new);
                                let right_parent_hash =
                                    right.parent_hash().unwrap_or_else(Vec::new);
                                if (left_parent_hash != own_hash) && (right_parent_hash != own_hash)
                                {
                                    return false;
                                }
                                if left_parent_hash == right_parent_hash {
                                    return false;
                                }
                            } else if right.parent_hash().unwrap() != own_hash {
                                return false;
                            }
                        } else if let Some(left) = left_option {
                            if left.parent_hash().unwrap() != own_hash {
                                return false;
                            }
                        }
                    }
                    NodeType::Leaf => {
                        if let Some(kp) = &node.key_package {
                            if i % 2 != 0 {
                                return false;
                            }
                            if !kp.verify() {
                                return false;
                            }
                        }
                    }

                    NodeType::Default => {}
                }
            }
        }
        true
    }
}

pub type InvitationList = Vec<(NodeIndex, AddProposal)>;

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<0..2^32-1>;
/// } UpdatePathNode;
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct UpdatePathNode {
    pub public_key: HPKEPublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     KeyPackage leaf_key_package;
///     UpdatePathNode nodes<0..2^32-1>;
/// } UpdatePath;
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>,
}

impl UpdatePath {
    /// Create a new update path.
    fn new(leaf_key_package: KeyPackage, nodes: Vec<UpdatePathNode>) -> Self {
        Self {
            leaf_key_package,
            nodes,
        }
    }
}

/// These are errors the RatchetTree can return.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TreeError {
    InvalidArguments,
    NoneError,
    DuplicateIndex,
    InvalidUpdatePath,
}