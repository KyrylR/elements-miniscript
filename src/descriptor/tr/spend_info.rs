// SPDX-License-Identifier: CC0-1.0

//! Taproot Spending Information
//!
//! Provides a structure which can be used to obtain control blocks and other information
//! needed for Taproot spends.
//!

use std::sync::Arc;

use elements::hashes::{sha256t, HashEngine};
use elements::schnorr::{TapTweak as _, TweakedPublicKey, UntweakedPublicKey};
use elements::secp256k1_zkp::{Parity, Secp256k1};
use elements::taproot::{
    ControlBlock, LeafVersion, TapBranchTag, TapLeafHash, TapNodeHash, TaprootBuilder,
    TaprootMerkleBranch, TAPROOT_CONTROL_MAX_NODE_COUNT,
};
use elements::{pset, Script};

use crate::extensions::ParseableExt;
use crate::miniscript::context::Tap;
use crate::{Extension, Miniscript, MiniscriptKey, NoExt, ToPublicKey};

/// Utility structure which maintains a stack of bits (at most 128) using a u128.
///
/// The caller must not push more than 128 bits. This module starts with a
/// validated [`super::TapTree`], whose depth limit enforces that bound.
#[derive(Default)]
struct BitStack128 {
    inner: u128,
    height: u8,
}

impl BitStack128 {
    fn push(&mut self, bit: bool) {
        if bit {
            self.inner |= 1u128 << self.height;
        } else {
            self.inner &= !(1u128 << self.height);
        }
        self.height += 1;
    }

    fn pop(&mut self) -> Option<bool> {
        if self.height > 0 {
            self.height -= 1;
            Some(self.inner & (1u128 << self.height) != 0)
        } else {
            None
        }
    }
}

/// Stack of `(bool, usize)` elements, with a maximum capacity of `TAPROOT_CONTROL_MAX_NODE_COUNT`.
///
/// Avoids heap allocation. Flags and indices are kept apart because a pair would be
/// padded to 16 bytes, twice what an index needs.
struct ParentStack {
    done_left: BitStack128,
    indices: [usize; TAPROOT_CONTROL_MAX_NODE_COUNT],
}

impl ParentStack {
    fn new() -> Self {
        Self {
            done_left: BitStack128::default(),
            indices: [0; TAPROOT_CONTROL_MAX_NODE_COUNT],
        }
    }

    fn push(&mut self, val: (bool, usize)) {
        // The stack never grows past the depth of a leaf, and a `TapTree` cannot be built with
        // leaves deeper than `TAPROOT_CONTROL_MAX_NODE_COUNT`, so the last index written is
        // `TAPROOT_CONTROL_MAX_NODE_COUNT - 1` and `indices` is exactly big enough.
        let (done_left_child, index) = val;

        // Written first: the bounds check is active in release, the shift in `BitStack128` is not.
        self.indices[self.len()] = index;
        self.done_left.push(done_left_child);
    }

    fn pop(&mut self) -> Option<(bool, usize)> {
        let done_left_child = self.done_left.pop()?;
        Some((done_left_child, self.indices[self.len()]))
    }

    fn len(&self) -> usize {
        usize::from(self.done_left.height)
    }
}

/// Computes the hash of a branch node from the hashes of its children.
///
/// The children are hashed in lexicographic order, as in Elements `NodeInfo::combine`.
fn branch_hash(a: TapNodeHash, b: TapNodeHash) -> TapNodeHash {
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    let mut eng = sha256t::Hash::<TapBranchTag>::engine();
    eng.input(a.as_byte_array());
    eng.input(b.as_byte_array());
    TapNodeHash::from_byte_array(eng.finalize().to_byte_array())
}

/// A structure which can be used to obtain control blocks and other information
/// needed for Taproot spends.
///
/// Conceptually, this object is a copy of the Taproot tree with each leaf annotated
/// with extra information that can be used to compute its control block.
pub struct TrSpendInfo<Pk: MiniscriptKey, Ext: Extension = NoExt> {
    internal_key: UntweakedPublicKey,
    output_key: TweakedPublicKey,
    output_key_parity: Parity,
    /// The nodes of the tree, in pre-order, i.e. left-to-right depth-first order.
    nodes: Vec<TrSpendInfoNode<Pk, Ext>>,
}

impl<Pk: ToPublicKey, Ext: ParseableExt> TrSpendInfo<Pk, Ext> {
    fn nodes_from_tap_tree(tree: &super::TapTree<Pk, Ext>) -> Vec<TrSpendInfoNode<Pk, Ext>> {
        let mut nodes = vec![];
        let mut parent_stack = ParentStack::new();
        for leaf in tree.leaves() {
            let depth = usize::from(leaf.depth());
            let script = leaf.miniscript().encode();

            let leaf_hash = TapLeafHash::from_script(&script, leaf.leaf_version());
            let mut current_hash = TapNodeHash::from_byte_array(leaf_hash.to_byte_array());

            while parent_stack.len() < depth {
                // When we encounter a leaf we put all of its parent nodes into the
                // result. We set the "sibling hash" to a dummy value (specifically,
                // `current_hash`, because it's convenient and the right type).
                parent_stack.push((false, nodes.len()));
                nodes.push(TrSpendInfoNode {
                    sibling_hash: current_hash,
                    leaf_data: None,
                });
            }
            // If parent_stack.len() < depth then we pushed things onto the stack in
            // the previous step so that we now have equality. Meanwhile, it is
            // impossible for parent_stack.len() > depth because we pop things off
            // the stack below.
            assert_eq!(depth, parent_stack.len());

            // Again, we don't know the sibling hash yet so we use the current hash.
            // But this time the current hash isn't an arbitrary dummy value. In the
            // next step we will have an invariant that incomplete nodes' "sibling hashes"
            // are set to the nodes' own hashes.
            //
            // We will use this hash to compute the parent's hash then replace it with
            // the actual sibling hash. We do this for every node EXCEPT the root node,
            // whose "sibling hash" will then wind up being equal to the Merkle root
            // of the whole tree.
            nodes.push(TrSpendInfoNode {
                sibling_hash: current_hash,
                leaf_data: Some(LeafData {
                    script,
                    miniscript: Arc::clone(leaf.miniscript()),
                    leaf_hash,
                }),
            });

            // Recursively complete nodes as long as we are on a right branch.
            //
            // As described above, for each parent node, we compute its hash and store it
            // in `sibling_hash`. At that point we're done with the childrens' hashes so
            // we finally replace those with their sibling hashes.
            let mut cur_index = nodes.len() - 1;
            while let Some((done_left_child, parent_idx)) = parent_stack.pop() {
                if done_left_child {
                    let lchild_hash = nodes[parent_idx + 1].sibling_hash;
                    let new_merkle_root = branch_hash(lchild_hash, current_hash);
                    nodes[parent_idx].sibling_hash = new_merkle_root;
                    nodes[parent_idx + 1].sibling_hash = current_hash;
                    nodes[cur_index].sibling_hash = lchild_hash;
                    current_hash = new_merkle_root;
                    cur_index = parent_idx;
                } else {
                    // Once we hit a left branch we can't do anything until we see the next leaf.
                    parent_stack.push((true, parent_idx));
                    break;
                }
            }
        }
        debug_assert_eq!(parent_stack.len(), 0);
        debug_assert_ne!(nodes.len(), 0);

        nodes
    }

    /// Constructs a [`TrSpendInfo`] for a [`super::Tr`].
    pub fn from_tr(tr: &super::Tr<Pk, Ext>) -> Self {
        let internal_key = tr.internal_key().to_x_only_pubkey();

        let nodes = match tr.tap_tree() {
            Some(tree) => Self::nodes_from_tap_tree(tree),
            None => vec![],
        };

        let secp = Secp256k1::verification_only();
        let (output_key, output_key_parity) =
            internal_key.tap_tweak(&secp, nodes.first().map(|node| node.sibling_hash));

        Self {
            internal_key,
            output_key,
            output_key_parity,
            nodes,
        }
    }

    /// If this [`TrSpendInfo`] has an associated Taproot tree, return its Merkle root.
    pub fn merkle_root(&self) -> Option<TapNodeHash> {
        // As described in `nodes_from_tap_tree`, the "sibling hash" of the root node
        // is actually the Merkle root of the whole tree.
        self.nodes.first().map(|node| node.sibling_hash)
    }

    /// The internal key of the Taproot output, as an untweaked x-only key.
    ///
    /// The witness program of the output contains [`Self::output_key`] instead. Script
    /// path spends reveal the internal key in their control blocks. For the key in its
    /// original type, use the `internal_key` method on the original [`super::Tr`].
    pub fn internal_key(&self) -> UntweakedPublicKey {
        self.internal_key
    }

    /// The external key of the Taproot output.
    #[doc(alias = "external_key")]
    pub fn output_key(&self) -> TweakedPublicKey {
        self.output_key
    }

    /// The parity of the external key of the Taproot output.
    #[doc(alias = "external_key_parity")]
    pub fn output_key_parity(&self) -> Parity {
        self.output_key_parity
    }

    /// An iterator over the leaves of the Taptree.
    ///
    /// This yields the same leaves in the same order as [`super::Tr::leaves`] on the original
    /// [`super::Tr`]. However, in addition to yielding the leaves and their depths, it also
    /// yields their scripts, leafhashes, and control blocks.
    pub fn leaves(&self) -> TrSpendInfoIter<'_, Pk, Ext> {
        // No leaf of a tree with `n` nodes is deeper than `n / 2`.
        let max_depth = (self.nodes.len() / 2).min(TAPROOT_CONTROL_MAX_NODE_COUNT);
        TrSpendInfoIter {
            spend_info: self,
            index: 0,
            merkle_stack: Vec::with_capacity(max_depth),
            done_left_stack: BitStack128::default(),
        }
    }

    /// If the Taproot tree is not keyspend-only, converts it to a [`pset::TapTree`] structure.
    pub fn to_tap_tree(&self) -> Option<pset::TapTree> {
        if self.nodes.is_empty() {
            return None;
        }

        let mut builder = TaprootBuilder::new();
        for leaf in self.leaves() {
            builder = builder
                .add_leaf_with_ver(
                    usize::from(leaf.depth()),
                    leaf.script().clone(),
                    leaf.leaf_version(),
                )
                .expect("iterating through tree in correct DFS order")
        }
        Some(pset::TapTree::from_inner(builder).expect("tree is complete"))
    }
}

#[derive(Debug)]
struct TrSpendInfoNode<Pk: MiniscriptKey, Ext: Extension> {
    sibling_hash: TapNodeHash,
    leaf_data: Option<LeafData<Pk, Ext>>,
}

#[derive(Debug)]
struct LeafData<Pk: MiniscriptKey, Ext: Extension> {
    script: Script,
    miniscript: Arc<Miniscript<Pk, Tap, Ext>>,
    leaf_hash: TapLeafHash,
}

/// An iterator over the leaves of a Taproot tree. Produced by [`TrSpendInfo::leaves`].
///
/// This is conceptually similar to [`super::TapTreeIter`], which can be obtained by
/// calling [`super::TapTree::leaves`]. That iterator goes over the leaves of the tree,
/// yielding the Miniscripts of the leaves and their depth.
///
/// This iterator goes over the leaves in the same order, yielding the data that actually
/// goes on chain: their scripts, control blocks, etc.
pub struct TrSpendInfoIter<'sp, Pk: MiniscriptKey, Ext: Extension = NoExt> {
    spend_info: &'sp TrSpendInfo<Pk, Ext>,
    index: usize,
    merkle_stack: Vec<TapNodeHash>,
    done_left_stack: BitStack128,
}

impl<'sp, Pk: MiniscriptKey, Ext: Extension> Iterator for TrSpendInfoIter<'sp, Pk, Ext> {
    type Item = TrSpendInfoIterItem<'sp, Pk, Ext>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.spend_info.nodes.len() {
            let current_node = &self.spend_info.nodes[self.index];
            if self.index > 0 {
                self.merkle_stack.push(current_node.sibling_hash);
            }
            self.index += 1;

            if let Some(ref leaf) = current_node.leaf_data {
                let mut merkle_stack = self.merkle_stack.clone();
                merkle_stack.reverse();
                self.merkle_stack.pop();

                loop {
                    match self.done_left_stack.pop() {
                        None => break, // this leaf is the root node
                        Some(false) => {
                            self.done_left_stack.push(true);
                            break;
                        }
                        Some(true) => {
                            self.merkle_stack.pop();
                        }
                    }
                }

                return Some(TrSpendInfoIterItem {
                    script: &leaf.script,
                    miniscript: &leaf.miniscript,
                    leaf_hash: leaf.leaf_hash,
                    control_block: ControlBlock {
                        leaf_version: LeafVersion::default(),
                        output_key_parity: self.spend_info.output_key_parity,
                        internal_key: self.spend_info.internal_key,
                        merkle_branch: TaprootMerkleBranch::from_inner(merkle_stack)
                            .expect("merkle stack guaranteed to be within allowable length"),
                    },
                });
            } else {
                self.done_left_stack.push(false);
            }
        }
        None
    }
}

/// Item yielded from a [`TrSpendInfoIter`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrSpendInfoIterItem<'tr, Pk: MiniscriptKey, Ext: Extension = NoExt> {
    script: &'tr Script,
    miniscript: &'tr Arc<Miniscript<Pk, Tap, Ext>>,
    leaf_hash: TapLeafHash,
    control_block: ControlBlock,
}

impl<'sp, Pk: MiniscriptKey, Ext: Extension> TrSpendInfoIterItem<'sp, Pk, Ext> {
    /// The Tapscript of this leaf.
    #[inline]
    pub fn script(&self) -> &'sp Script {
        self.script
    }

    /// The Tapscript of this leaf, in Miniscript form.
    #[inline]
    pub fn miniscript(&self) -> &'sp Arc<Miniscript<Pk, Tap, Ext>> {
        self.miniscript
    }

    /// The depth of the leaf in the tree.
    ///
    /// This value is returned as `u8` since it is guaranteed to be <= 128 by the Taproot
    /// consensus rules.
    #[inline]
    pub fn depth(&self) -> u8 {
        self.control_block.merkle_branch.as_inner().len() as u8 // cast ok, length limited to 128
    }

    /// The Tapleaf version of this leaf.
    ///
    /// This function returns a constant value, the Elements Tapscript leaf
    /// version, which is the only version Miniscript leaves use.
    #[inline]
    pub fn leaf_version(&self) -> LeafVersion {
        self.control_block.leaf_version
    }

    /// The hash of this leaf.
    #[inline]
    pub fn leaf_hash(&self) -> TapLeafHash {
        self.leaf_hash
    }

    /// The control block of this leaf.
    ///
    /// Unlike the other data obtainable from [`TrSpendInfoIterItem`], this one is computed
    /// dynamically during iteration and therefore will not outlive the iterator item. See
    /// [`Self::into_control_block`], which consumes the iterator item but will give you an
    /// owned copy of the control block.
    ///
    /// If you need access to multiple control blocks at once, you may need to `clone` the
    /// return value of this method, or call [`Self::into_control_block`], and store the
    /// result in a separate container.
    #[inline]
    pub fn control_block(&self) -> &ControlBlock {
        &self.control_block
    }

    /// Extract the control block of this leaf, consuming `self`.
    #[inline]
    pub fn into_control_block(self) -> ControlBlock {
        self.control_block
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::descriptor::{TapTree, Tr};
    use crate::extensions::{CovExtArgs, CovenantExt};

    type Ms = Miniscript<bitcoin::PublicKey, Tap>;

    /// Builds a tree from a description in which each leaf is a Miniscript
    /// and each branch is written `{left,right}`.
    ///
    /// Leaves are parsed without sanity checks so that fixed scripts such as `0`
    /// can be used.
    fn tree(s: &str) -> TapTree<bitcoin::PublicKey> {
        fn split(s: &str) -> (&str, &str) {
            let mut depth = 0;
            for (i, ch) in s.char_indices() {
                match ch {
                    '{' | '(' => depth += 1,
                    '}' | ')' => depth -= 1,
                    ',' if depth == 0 => return (&s[..i], &s[i + 1..]),
                    _ => {}
                }
            }
            panic!("no top-level comma in {}", s)
        }
        match s.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(inner) => {
                let (left, right) = split(inner);
                TapTree::combine(tree(left), tree(right)).unwrap()
            }
            None => TapTree::leaf(Ms::from_str_insane(s).unwrap()),
        }
    }

    fn test_trees() -> Vec<Option<&'static str>> {
        vec![
            // Key spend only
            None,
            // Single leaf
            Some("0"),
            Some("pk(03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115)"),
            // Two leaves, repeated and distinct
            Some("{0,0}"),
            Some("{0,1}"),
            // Shapes of the upstream fuzz test vectors
            Some("{0,{0,tv:0}}"),
            Some("{uuu:0,{0,uu:0}}"),
            Some("{{0,{uuu:0,0}},{0,uu:0}}"),
            // Unbalanced trees in both directions, and repeated leaves at different depths
            Some("{{{0,1},uu:0},{tv:0,0}}"),
            Some("{1,{1,{1,{1,0}}}}"),
            Some("{{{{0,1},1},1},1}"),
        ]
    }

    /// Combs in both directions, whose two deepest leaves are at depth 128.
    fn maximum_depth_trees() -> Vec<(Option<&'static str>, Option<TapTree<bitcoin::PublicKey>>)> {
        let (mut left, mut right) = (tree("0"), tree("0"));
        for i in 0..TAPROOT_CONTROL_MAX_NODE_COUNT {
            let leaf = tree(["0", "1"][i % 2]);
            left = TapTree::combine(left, leaf.clone()).unwrap();
            right = TapTree::combine(leaf, right).unwrap();
        }
        for comb in [&left, &right] {
            assert_eq!(comb.leaves().map(|leaf| leaf.depth()).max(), Some(128));
        }
        vec![
            (Some("left comb"), Some(left)),
            (Some("right comb"), Some(right)),
        ]
    }

    // Checks the spend info against the independent `TaprootBuilder` implementation
    // in rust-elements, and checks each control block with
    // `ControlBlock::verify_taproot_commitment`.
    #[test]
    fn spend_info_matches_elements_taproot_builder() {
        let secp = Secp256k1::verification_only();
        let pk = bitcoin::PublicKey::from_str(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();

        let trees = test_trees()
            .into_iter()
            .map(|desc| (desc, desc.map(tree)))
            .chain(maximum_depth_trees());
        for (desc, tap_tree) in trees {
            let tr = Tr::new(pk, tap_tree.clone()).unwrap();
            let spend_info = tr.spend_info();

            let mut builder = TaprootBuilder::new();
            if let Some(ref tap_tree) = tap_tree {
                for leaf in tap_tree.leaves() {
                    builder = builder
                        .add_leaf(usize::from(leaf.depth()), leaf.compute_script())
                        .unwrap();
                }
            }
            let expected = if tap_tree.is_some() {
                builder.finalize(&secp, pk.to_x_only_pubkey()).unwrap()
            } else {
                elements::taproot::TaprootSpendInfo::new_key_spend(
                    &secp,
                    pk.to_x_only_pubkey(),
                    None,
                )
            };

            assert_eq!(
                spend_info.internal_key(),
                expected.internal_key(),
                "{:?}",
                desc
            );
            assert_eq!(
                spend_info.merkle_root(),
                expected.merkle_root(),
                "{:?}",
                desc
            );
            assert_eq!(spend_info.output_key(), expected.output_key(), "{:?}", desc);
            assert_eq!(
                spend_info.output_key_parity(),
                expected.output_key_parity(),
                "{:?}",
                desc
            );

            let leaves: Vec<_> = spend_info.leaves().collect();
            let tree_leaves: Vec<_> = tap_tree.iter().flat_map(TapTree::leaves).collect();
            assert_eq!(leaves.len(), tree_leaves.len(), "{:?}", desc);
            for (leaf, tree_leaf) in leaves.iter().zip(tree_leaves.iter()) {
                assert_eq!(leaf.depth(), tree_leaf.depth(), "{:?}", desc);
                assert_eq!(leaf.miniscript(), tree_leaf.miniscript(), "{:?}", desc);
                assert_eq!(leaf.script(), &tree_leaf.compute_script(), "{:?}", desc);
                assert_eq!(
                    leaf.leaf_hash(),
                    tree_leaf.compute_tap_leaf_hash(),
                    "{:?}",
                    desc
                );
                assert_eq!(leaf.leaf_version(), LeafVersion::default(), "{:?}", desc);

                let script_ver = (leaf.script().clone(), leaf.leaf_version());
                let branches = expected.as_script_map().get(&script_ver).unwrap();
                assert!(
                    branches.contains(&leaf.control_block().merkle_branch),
                    "{:?}",
                    desc
                );
                assert!(leaf.control_block().verify_taproot_commitment(
                    &secp,
                    &spend_info.output_key(),
                    leaf.script(),
                ));
            }

            match (spend_info.to_tap_tree(), tap_tree) {
                (None, None) => {}
                (Some(pset_tree), Some(_)) => {
                    let builder = pset_tree.into_inner();
                    let from_pset = builder.finalize(&secp, pk.to_x_only_pubkey()).unwrap();
                    assert_eq!(
                        from_pset.merkle_root(),
                        spend_info.merkle_root(),
                        "{:?}",
                        desc
                    );
                }
                _ => panic!("tap tree mismatch for {:?}", desc),
            }
        }
    }

    // Leaves with extensions are encoded with their extension opcodes.
    #[test]
    fn spend_info_with_extensions() {
        let secp = Secp256k1::verification_only();
        let desc = "eltr(03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{pk(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0),and_v(v:pk(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4),is_exp_asset(out_asset(0)))})";
        let tr = Tr::<bitcoin::PublicKey, CovenantExt<CovExtArgs>>::from_str(desc).unwrap();
        let spend_info = tr.spend_info();
        for leaf in spend_info.leaves() {
            assert_eq!(leaf.script(), &leaf.miniscript().encode());
            assert!(leaf.control_block().verify_taproot_commitment(
                &secp,
                &spend_info.output_key(),
                leaf.script(),
            ));
        }
        assert_eq!(spend_info.leaves().count(), 2);
    }
}
