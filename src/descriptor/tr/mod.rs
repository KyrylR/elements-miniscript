// SPDX-License-Identifier: CC0-1.0

use std::sync::{Arc, Mutex};
use std::{cmp, fmt, hash};

use elements::taproot::{TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE};
use elements::{self, opcodes, secp256k1_zkp, Script};

use super::checksum::verify_checksum;
use super::ELMTS_STR;
use crate::descriptor::checksum;
use crate::expression::{self, FromTree, Parens};
use crate::extensions::ParseableExt;
use crate::miniscript::analyzable::ExtParams;
use crate::miniscript::Miniscript;
use crate::policy::semantic::Policy;
use crate::policy::Liftable;
use crate::util::varint_len;
use crate::{
    Error, ExtTranslator, Extension, ForEachKey, MiniscriptKey, NoExt, Satisfier, Tap, ToPublicKey,
    TranslateExt, TranslatePk, Translator,
};

mod spend_info;
mod taptree;

pub use self::spend_info::{TrSpendInfo, TrSpendInfoIter, TrSpendInfoIterItem};
pub use self::taptree::{TapTree, TapTreeDepthError, TapTreeIter, TapTreeIterItem};

/// A taproot descriptor
pub struct Tr<Pk: MiniscriptKey, Ext: Extension = NoExt> {
    internal_key: Pk,
    tree: Option<TapTree<Pk, Ext>>,
    // The inner `Arc` here is because Rust does not allow us to return a reference
    // to the contents of the `Option` from inside a `MutexGuard`. There is no outer
    // `Arc` because each clone gets its own mutex, so clones don't block each other.
    spend_info: Mutex<Option<Arc<TrSpendInfo<Pk, Ext>>>>,
}

impl<Pk: MiniscriptKey, Ext: Extension> Clone for Tr<Pk, Ext> {
    fn clone(&self) -> Self {
        Self {
            internal_key: self.internal_key.clone(),
            tree: self.tree.clone(),
            spend_info: Mutex::new(
                self.spend_info
                    .lock()
                    .expect("Lock poisoned")
                    .as_ref()
                    .map(Arc::clone),
            ),
        }
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> PartialEq for Tr<Pk, Ext> {
    fn eq(&self, other: &Self) -> bool {
        self.internal_key == other.internal_key && self.tree == other.tree
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> Eq for Tr<Pk, Ext> {}

impl<Pk: MiniscriptKey, Ext: Extension> PartialOrd for Tr<Pk, Ext> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> Ord for Tr<Pk, Ext> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.internal_key.cmp(&other.internal_key) {
            cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.tree.cmp(&other.tree)
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> hash::Hash for Tr<Pk, Ext> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.internal_key.hash(state);
        self.tree.hash(state);
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> Tr<Pk, Ext> {
    /// Create a new [`Tr`] descriptor from internal key and [`TapTree`]
    pub fn new(internal_key: Pk, tree: Option<TapTree<Pk, Ext>>) -> Result<Self, Error> {
        Ok(Self {
            internal_key,
            tree,
            spend_info: Mutex::new(None),
        })
    }

    /// Obtain the internal key of [`Tr`] descriptor
    pub fn internal_key(&self) -> &Pk {
        &self.internal_key
    }

    /// Obtain the [`TapTree`] of the [`Tr`] descriptor
    pub fn tap_tree(&self) -> Option<&TapTree<Pk, Ext>> {
        self.tree.as_ref()
    }

    /// Iterates over all the leaves of the tree in depth-first preorder.
    ///
    /// The yielded elements include the Miniscript for each leaf as well as its depth
    /// in the tree, which is the data required by PSET.
    pub fn leaves(&self) -> TapTreeIter<'_, Pk, Ext> {
        match self.tree {
            Some(ref t) => t.leaves(),
            None => TapTreeIter::empty(),
        }
    }

    /// Obtain the spending information for this [`Tr`].
    ///
    /// The first time this method is called, it computes the full Taproot Merkle tree of
    /// all branches as well as the output key which appears on-chain. This is fairly
    /// expensive since it requires hashing every branch and then doing an elliptic curve
    /// operation. The result is cached and reused on subsequent calls.
    ///
    /// This data is needed to compute the Taproot output, so this method is implicitly
    /// called through [`Self::script_pubkey`], [`Self::address`], etc. It is also needed
    /// to compute the hash needed to sign the output.
    pub fn spend_info(&self) -> Arc<TrSpendInfo<Pk, Ext>>
    where
        Pk: ToPublicKey,
        Ext: ParseableExt,
    {
        let mut lock = self.spend_info.lock().expect("Lock poisoned");
        match *lock {
            Some(ref res) => Arc::clone(res),
            None => {
                let arc = Arc::new(TrSpendInfo::from_tr(self));
                *lock = Some(Arc::clone(&arc));
                arc
            }
        }
    }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        for leaf in self.leaves() {
            leaf.miniscript().sanity_check()?;
        }
        Ok(())
    }

    /// Computes an upper bound on the difference between a non-satisfied
    /// `TxIn`'s `segwit_weight` and a satisfied `TxIn`'s `segwit_weight`
    ///
    /// Assumes all Schnorr signatures are 65 bytes, including the sighash type,
    /// plus a 1-byte witness length prefix.
    ///
    /// # Errors
    /// When no leaf of the script tree can be satisfied.
    pub fn max_weight_to_satisfy(&self) -> Result<usize, Error> {
        let tree = match self.tap_tree() {
            None => {
                // key spend path
                // item: varint(sig+sigHash) + <sig(64)+sigHash(1)>
                let item_sig_size = 1 + 65;
                // 1 stack item
                let stack_varint_diff = varint_len(1) - varint_len(0);

                return Ok(stack_varint_diff + item_sig_size);
            }
            // script path spend..
            Some(tree) => tree,
        };

        tree.leaves()
            .filter_map(|leaf| {
                let script_size = leaf.miniscript().script_size();
                let max_sat_elems = leaf.miniscript().max_satisfaction_witness_elements().ok()?;
                let max_sat_size = leaf.miniscript().max_satisfaction_size().ok()?;
                let control_block_size = control_block_len(leaf.depth());

                // stack varint difference (+1 for ctrl block, witness script already included)
                let stack_varint_diff = varint_len(max_sat_elems + 1) - varint_len(0);

                Some(
                    stack_varint_diff +
                    // size of elements to satisfy script
                    max_sat_size +
                    // second to last element: script
                    varint_len(script_size) +
                    script_size +
                    // last element: control block
                    varint_len(control_block_size) +
                    control_block_size,
                )
            })
            .max()
            .ok_or(Error::ImpossibleSatisfaction)
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction.
    ///
    /// Assumes all Schnorr signatures are 65 bytes, including the sighash type,
    /// plus a 1-byte witness length prefix. Includes the weight of the VarInts
    /// encoding the scriptSig and witness stack length.
    ///
    /// # Errors
    /// When no leaf of the script tree can be satisfied.
    #[deprecated(note = "use max_weight_to_satisfy instead")]
    pub fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        let tree = match self.tap_tree() {
            // key spend path:
            // scriptSigLen(4) + stackLen(1) + stack[Sig]Len(1) + stack[Sig](65)
            None => return Ok(4 + 1 + 1 + 65),
            // script path spend..
            Some(tree) => tree,
        };

        tree.leaves()
            .filter_map(|leaf| {
                let script_size = leaf.miniscript().script_size();
                let max_sat_elems = leaf.miniscript().max_satisfaction_witness_elements().ok()?;
                let max_sat_size = leaf.miniscript().max_satisfaction_size().ok()?;
                let control_block_size = control_block_len(leaf.depth());
                Some(
                    // scriptSig len byte
                    4 +
                    // witness field stack len (+2 for control block & script)
                    varint_len(max_sat_elems + 2) +
                    // size of elements to satisfy script
                    max_sat_size +
                    // second to last element: script
                    varint_len(script_size) +
                    script_size +
                    // last element: control block
                    varint_len(control_block_size) +
                    control_block_size,
                )
            })
            .max()
            .ok_or(Error::ImpossibleSatisfaction)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey, Ext: ParseableExt> Tr<Pk, Ext> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> Script {
        let output_key = self.spend_info().output_key();
        let builder = elements::script::Builder::new();
        builder
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_slice(&output_key.as_inner().serialize())
            .into_script()
    }

    /// Obtains the corresponding address for this descriptor.
    pub fn address(
        &self,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static elements::AddressParams,
    ) -> elements::Address {
        let spend_info = self.spend_info();
        elements::Address::p2tr_tweaked(spend_info.output_key(), blinder, params)
    }

    /// Returns satisfying non-malleable witness and scriptSig with minimum
    /// weight to spend an output controlled by the given descriptor if it is
    /// possible to construct one using the `satisfier`.
    pub fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        S: Satisfier<Pk>,
    {
        best_tap_spend(self, satisfier, false /* allow_mall */)
    }

    /// Returns satisfying, possibly malleable, witness and scriptSig with
    /// minimum weight to spend an output controlled by the given descriptor if
    /// it is possible to construct one using the `satisfier`.
    pub fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        S: Satisfier<Pk>,
    {
        best_tap_spend(self, satisfier, true /* allow_mall */)
    }
}

impl_from_tree!(
    Tr<Pk, Ext>,
    => Ext; Extension,
    fn from_tree(root: expression::TreeIterItem<'_>) -> Result<Self, Error> {
        use bitcoin_miniscript::ParseTreeError;

        let key = root.verify_toplevel("eltr", 1..=2)?;
        let internal_key = expression::terminal(key, Pk::from_str)?;

        let tap_tree = match key.right_sibling() {
            None => return Self::new(internal_key, None),
            Some(tree) => tree,
        };

        let mut tree_builder = taptree::TapTreeBuilder::new();
        let mut tap_tree_iter = tap_tree.pre_order_iter();
        // while let construction needed because we modify the iterator inside the loop
        // (by calling skip_descendants to skip over the contents of the tapscripts).
        while let Some(node) = tap_tree_iter.next() {
            if node.parens() == Parens::Curly {
                if !node.name().is_empty() {
                    return Err(Error::from(ParseTreeError::IncorrectName {
                        actual: node.name().to_owned(),
                        expected: "",
                    }));
                }
                node.verify_n_children("taptree branch", 2..=2)?;
                tree_builder.push_inner_node()?;
            } else {
                let script = Miniscript::<Pk, Tap, Ext>::from_tree_ext(node, &ExtParams::sane())?;
                tree_builder.push_leaf(script);
                tap_tree_iter.skip_descendants();
            }
        }
        Self::new(internal_key, Some(tree_builder.finalize()))
    }
);

impl_from_str!(
    Tr<Pk, Ext>,
    => Ext; Extension,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(top.root())
    }
);

impl<Pk: MiniscriptKey, Ext: Extension> fmt::Debug for Tr<Pk, Ext> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tree {
            Some(ref s) => write!(f, "tr({:?},{:?})", self.internal_key, s),
            None => write!(f, "tr({:?})", self.internal_key),
        }
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> fmt::Display for Tr<Pk, Ext> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;
        let mut wrapped_f = checksum::Formatter::new(f);
        let key = &self.internal_key;
        match self.tree {
            Some(ref s) => write!(wrapped_f, "{}tr({},{})", ELMTS_STR, key, s)?,
            None => write!(wrapped_f, "{}tr({})", ELMTS_STR, key)?,
        }
        wrapped_f.write_checksum_if_not_alt()
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> Liftable<Pk> for Tr<Pk, Ext> {
    fn lift(&self) -> Result<Policy<Pk>, Error> {
        match &self.tree {
            Some(root) => Ok(Policy::Threshold(
                1,
                vec![Policy::Key(self.internal_key.clone()), root.lift()?],
            )),
            None => Ok(Policy::Key(self.internal_key.clone())),
        }
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> ForEachKey<Pk> for Tr<Pk, Ext> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
    {
        let script_keys_res = self
            .leaves()
            .all(|leaf| leaf.miniscript().for_each_key(&mut pred));
        script_keys_res && pred(&self.internal_key)
    }
}

impl<P, Q, Ext> TranslatePk<P, Q> for Tr<P, Ext>
where
    P: MiniscriptKey,
    Q: MiniscriptKey,
    Ext: Extension,
{
    type Output = Tr<Q, Ext>;

    /// Translates the internal key before the script tree, preserving textual key order.
    fn translate_pk<T, E>(&self, translate: &mut T) -> Result<Self::Output, E>
    where
        T: Translator<P, Q, E>,
    {
        let internal_key = translate.pk(&self.internal_key)?;
        let tree = match &self.tree {
            Some(tree) => Some(tree.translate_pk(translate)?),
            None => None,
        };
        Ok(Tr {
            internal_key,
            tree,
            spend_info: Mutex::new(None),
        })
    }
}

impl<PExt, QExt, Pk> TranslateExt<PExt, QExt> for Tr<Pk, PExt>
where
    PExt: Extension + TranslateExt<PExt, QExt, Output = QExt>,
    QExt: Extension,
    Pk: MiniscriptKey,
{
    type Output = Tr<Pk, QExt>;

    fn translate_ext<T, E>(&self, translator: &mut T) -> Result<Self::Output, E>
    where
        T: ExtTranslator<PExt, QExt, E>,
    {
        let tree = match &self.tree {
            Some(tree) => Some(tree.translate_ext(translator)?),
            None => None,
        };
        Ok(Tr {
            internal_key: self.internal_key.clone(),
            tree,
            spend_info: Mutex::new(None),
        })
    }
}

fn control_block_len(depth: u8) -> usize {
    TAPROOT_CONTROL_BASE_SIZE + (depth as usize) * TAPROOT_CONTROL_NODE_SIZE
}

fn best_tap_spend<Pk, S, Ext>(
    desc: &Tr<Pk, Ext>,
    satisfier: S,
    allow_mall: bool,
) -> Result<(Vec<Vec<u8>>, Script), Error>
where
    Pk: ToPublicKey,
    S: Satisfier<Pk>,
    Ext: ParseableExt,
{
    let spend_info = desc.spend_info();
    if let Some(sig) = satisfier.lookup_tap_key_spend_sig() {
        Ok((vec![sig.to_vec()], Script::new()))
    } else {
        let item_size = |len| varint_len(len) + len;
        let (mut min_wit, mut min_wit_len) = (None, None);
        for leaf in spend_info.leaves() {
            let mut wit = if allow_mall {
                match leaf.miniscript().satisfy_malleable(&satisfier) {
                    Ok(wit) => wit,
                    Err(..) => continue,
                }
            } else {
                match leaf.miniscript().satisfy(&satisfier) {
                    Ok(wit) => wit,
                    Err(..) => continue,
                }
            };
            // Serialized size of the witness with the script and the control block
            // pushed below: the item count, then each item with its length prefix.
            let wit_size = varint_len(wit.len() + 2)
                + wit.iter().map(|item| item_size(item.len())).sum::<usize>()
                + item_size(leaf.script().len())
                + item_size(control_block_len(leaf.depth()));

            if min_wit_len.is_some() && Some(wit_size) > min_wit_len {
                continue;
            } else {
                wit.push(leaf.script().to_bytes());
                wit.push(leaf.control_block().serialize());
                min_wit = Some(wit);
                min_wit_len = Some(wit_size);
            }
        }
        match min_wit {
            Some(wit) => Ok((wit, Script::new())),
            None => Err(Error::CouldNotSatisfy),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use elements::taproot::TapLeafHash;

    use super::*;

    type Ms = Miniscript<bitcoin::PublicKey, Tap>;

    fn strip_ws(desc: &str) -> String {
        desc.replace(&[' ', '\n'][..], "")
    }

    fn descriptor() -> String {
        let desc = "eltr(acc0, {
            {
              multi_a(3, acc10, acc11, acc12),
              and_v(
                v:multi_a(2, acc10, acc11, acc12),
                after(10)
              )
            },
            and_v(
              v:multi_a(1, acc10, acc11, ac12),
              after(100)
            )
         })";
        strip_ws(desc)
    }

    fn assert_display_roundtrip(desc: &str) {
        let desc = strip_ws(desc);
        let tr = Tr::<String>::from_str(&desc).unwrap();
        assert_eq!(format!("{:#}", tr), desc);
        Tr::<String>::from_str(&tr.to_string()).unwrap();
    }

    #[test]
    fn for_each() {
        let desc = descriptor();
        let tr = Tr::<String>::from_str(&desc).unwrap();
        // Note the last ac12 only has ac and fails the predicate
        assert!(!tr.for_each_key(|k| k.starts_with("acc")));
    }

    #[test]
    fn display_roundtrips_unbalanced_taptree() {
        assert_display_roundtrip(&descriptor());
        assert_display_roundtrip("eltr(acc0,{pk(acc1),{pk(acc2),pk(acc3)}})");
        assert_display_roundtrip("eltr(acc0,{{pk(acc1),pk(acc2)},{pk(acc3),pk(acc4)}})");
    }

    fn verify_from_str(desc_str: &str, internal_key: &str, scripts: &[&Miniscript<String, Tap>]) {
        let desc = Tr::<String, NoExt>::from_str(desc_str).unwrap();
        assert_eq!(desc_str, &desc.to_string());
        assert_eq!(internal_key, desc.internal_key());

        let desc_scripts: Vec<_> = desc.leaves().collect();
        assert_eq!(desc_scripts.len(), scripts.len());

        for (script, leaf) in scripts.iter().zip(desc_scripts.iter()) {
            assert_eq!(*script, &**leaf.miniscript());
        }
    }

    #[test]
    fn tr_from_str() {
        verify_from_str("eltr(internal)#0aen4jhp", "internal", &[]);

        let ms = Miniscript::<String, Tap>::from_str("pk(a)").unwrap();
        verify_from_str("eltr(internal,pk(a))#vadmk9gd", "internal", &[&ms]);
    }

    #[test]
    fn tr_script_tree_branches() {
        for s in [
            "eltr(A,pk(B))",
            "eltr(A,{pk(B),pk(C)})",
            "eltr(A,{pk(B),{pk(C),pk(D)}})",
            "eltr(musig(A,B),{pk(C),pk(D)})",
        ] {
            assert!(Tr::<String>::from_str(s).is_ok(), "{}", s);
        }
        // The script tree cannot be empty. Branches are nameless, use curly braces
        // and have exactly two children. Curly braces are not allowed anywhere else.
        for s in [
            "eltr",
            "eltr(A,pk(B),pk(C))",
            "eltr(A,)",
            "eltr(A,{})",
            "eltr(A,{pk(B)})",
            "eltr(A,{pk(B),pk(C),pk(D)})",
            "eltr(A,x{pk(B),pk(C)})",
            "eltr(A,(pk(B),pk(C)))",
            "eltr(A,and_v(v:pk(B),{pk(C),pk(D)}))",
            "eltr(A,{pk(B),pk{C}})",
            "eltr({A,B},pk(C))",
            "eltr{A,pk(B)}",
        ] {
            assert!(Tr::<String>::from_str(s).is_err(), "{}", s);
        }
    }

    #[test]
    fn tr_maximum_depth() {
        // A leaf at depth 128 is allowed, a leaf at depth 129 is not.
        fn nested(depth: usize) -> String {
            let mut s = String::from("eltr(X!,");
            for i in 1..=depth {
                s.push_str(&format!("{{pk(X{}!),", i));
            }
            s.push_str(&format!("pk(X{})", depth + 1));
            s.push_str(&"}".repeat(depth));
            s.push(')');
            s
        }
        let descriptor128 = nested(128);
        let tr = descriptor128.parse::<Tr<String>>().unwrap();
        assert_eq!(tr.leaves().map(|leaf| leaf.depth()).max(), Some(128));
        descriptor128.parse::<crate::Descriptor<String>>().unwrap();

        let descriptor129 = nested(129);
        assert!(matches!(
            descriptor129.parse::<Tr<String>>().unwrap_err(),
            Error::TapTreeDepthError(TapTreeDepthError),
        ));
        assert!(matches!(
            descriptor129
                .parse::<crate::Descriptor<String>>()
                .unwrap_err(),
            Error::TapTreeDepthError(TapTreeDepthError),
        ));
    }

    // The keys and the address of `examples/taproot.rs`.
    #[test]
    fn script_path_address() {
        let key = |bytes: [u8; 32]| bitcoin::key::XOnlyPublicKey::from_slice(&bytes).unwrap();
        let h_a = key([
            22, 37, 41, 4, 57, 254, 191, 38, 14, 184, 200, 133, 111, 226, 145, 183, 245, 112, 100,
            42, 69, 210, 146, 60, 179, 170, 174, 247, 231, 224, 221, 52,
        ]);
        let s = key([
            194, 16, 47, 19, 231, 1, 0, 143, 203, 11, 35, 148, 101, 75, 200, 15, 14, 54, 222, 208,
            31, 205, 191, 215, 80, 69, 214, 126, 10, 124, 107, 154,
        ]);
        let ca = key([
            202, 56, 167, 245, 51, 10, 193, 145, 213, 151, 66, 122, 208, 43, 10, 17, 17, 153, 170,
            29, 89, 133, 223, 134, 220, 212, 166, 138, 2, 152, 122, 16,
        ]);
        let in_key = key([
            50, 23, 194, 4, 213, 55, 42, 210, 67, 101, 23, 3, 195, 228, 31, 70, 127, 79, 21, 188,
            168, 39, 134, 58, 19, 181, 3, 63, 235, 103, 155, 213,
        ]);
        let desc = format!(
            "eltr({},{{and_v(v:pk({}),older(9)),multi_a(2,{},{})}})",
            ca, in_key, h_a, s
        );
        let tr = Tr::<bitcoin::key::XOnlyPublicKey>::from_str(&desc).unwrap();
        assert_eq!(
            tr.address(None, &elements::AddressParams::ELEMENTS),
            elements::Address::from_str(
                "ert1pxx6wkfdnnx97akwws8l8xdmx5n03qftvx2t269k4sn9adm2emz0sdnytn4"
            )
            .unwrap(),
        );
    }

    fn serialized_witness_size(witness: &[Vec<u8>]) -> usize {
        bitcoin::consensus::serialize(&bitcoin::Witness::from_slice(witness)).len()
    }

    // Checks that both satisfaction methods select the script
    // spend with the smallest serialized witness, and that this witness has `size` bytes.
    fn assert_smallest_script_spend<S: Satisfier<bitcoin::PublicKey>>(
        tr: &Tr<bitcoin::PublicKey>,
        satisfier: &S,
        size: usize,
    ) {
        let spend_info = tr.spend_info();
        for mall in [false, true] {
            let smallest = spend_info
                .leaves()
                .filter_map(|leaf| {
                    let satisfaction = if mall {
                        leaf.miniscript().satisfy_malleable(satisfier)
                    } else {
                        leaf.miniscript().satisfy(satisfier)
                    };
                    let mut witness = satisfaction.ok()?;
                    witness.push(leaf.script().to_bytes());
                    witness.push(leaf.control_block().serialize());
                    Some(witness)
                })
                .min_by_key(|witness| serialized_witness_size(witness))
                .unwrap();
            assert_eq!(serialized_witness_size(&smallest), size);

            let (witness, script_sig) = if mall {
                tr.get_satisfaction_mall(satisfier).unwrap()
            } else {
                tr.get_satisfaction(satisfier).unwrap()
            };
            assert_eq!(witness, smallest, "mall: {}", mall);
            assert!(script_sig.is_empty());
        }
    }

    fn test_key() -> bitcoin::PublicKey {
        bitcoin::PublicKey::from_str(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap()
    }

    fn leaf(ms: &str) -> TapTree<bitcoin::PublicKey> {
        TapTree::leaf(Ms::from_str_insane(ms).unwrap())
    }

    // A signature by `key` for every leaf of `tr`.
    fn signatures(
        tr: &Tr<bitcoin::PublicKey>,
        key: bitcoin::PublicKey,
    ) -> HashMap<(bitcoin::PublicKey, TapLeafHash), elements::SchnorrSig> {
        let sig = elements::SchnorrSig {
            sig: secp256k1_zkp::schnorr::Signature::from_str("84526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f0784526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07").unwrap(),
            hash_ty: elements::SchnorrSighashType::Default,
        };
        tr.spend_info()
            .leaves()
            .map(|leaf| ((key, leaf.leaf_hash()), sig))
            .collect()
    }

    #[test]
    fn smallest_signed_script_spend() {
        let key = test_key();
        // A 67-byte script at depth 6, with a 225-byte control block, and a 34-byte
        // script at depth 7, whose 257-byte control block needs a 3-byte length prefix.
        // Their witnesses are 360 and 361 bytes.
        let shallow = leaf(&format!("{}:pk({})", "n".repeat(33), key));
        let deep = leaf(&format!("pk({})", key));
        let mut tree =
            TapTree::combine(shallow, TapTree::combine(deep, leaf("0")).unwrap()).unwrap();
        for _ in 0..5 {
            tree = TapTree::combine(leaf("0"), tree).unwrap();
        }
        let tr = Tr::new(key, Some(tree)).unwrap();
        assert_smallest_script_spend(&tr, &signatures(&tr, key), 360);
    }

    #[test]
    fn smallest_script_spend_counts_witness_items() {
        let key = test_key();
        // `multi_a(1,..)` with `n` keys is satisfied with a signature and `n - 1` empty items.
        let multi_a = |n: usize| format!("multi_a(1{})", format!(",{}", key).repeat(n));
        // With the script and the control block, the first witness has 253 items,
        // whose count needs a 3-byte prefix, and the second one has 252 items and
        // a 2-byte longer script. Their witnesses are 8923 and 8922 bytes.
        let many_items = leaf(&multi_a(251));
        let fewer_items = leaf(&format!("{}:{}", "n".repeat(36), multi_a(250)));
        let tr = Tr::new(
            key,
            Some(TapTree::combine(many_items, fewer_items).unwrap()),
        )
        .unwrap();
        assert_smallest_script_spend(&tr, &signatures(&tr, key), 8922);
    }
}
