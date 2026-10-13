// SPDX-License-Identifier: CC0-1.0

//! Planning of Taproot spends.
//!
//! A plan is a witness template for one spending path of a Taproot descriptor.
//! It is built from the assets that will be available, such as the keys that can
//! sign, the hash preimages that are known and the timelocks that the spending
//! transaction will satisfy, before any signature exists. The template tells which
//! spending path is used and which locktime and sequence it requires. Once the
//! signatures and preimages exist, a [`Satisfier`] completes the template into a
//! witness.
//!
//! Plans are built by [`Tr::plan_satisfaction`] and [`Tr::plan_satisfaction_mall`].
//! Planning does not support extension fragments: their satisfactions and
//! dissatisfactions are unavailable in templates.
//!
//! [`Tr::plan_satisfaction`]: crate::descriptor::Tr::plan_satisfaction
//! [`Tr::plan_satisfaction_mall`]: crate::descriptor::Tr::plan_satisfaction_mall

use std::collections::BTreeSet;
use std::{cmp, mem};

use bitcoin::bip32;
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::secp256k1::XOnlyPublicKey;
use elements::taproot::{ControlBlock, TapLeafHash, TapNodeHash};
use elements::{LockTime, SchnorrSig, SchnorrSighashType, Script, Sequence};

use crate::util::varint_len;
use crate::{
    hash256, AbsLockTime, DefiniteDescriptorKey, Extension, Miniscript, MiniscriptKey, Satisfier,
    ScriptContext, Tap, Terminal, ToPublicKey,
};

/// Trait describing a present/missing lookup table for constructing witness templates
///
/// This trait mirrors the [`Satisfier`] trait, with the difference that most methods just return a
/// boolean indicating the item presence. The methods looking up signatures return their size,
/// 64 or 65 bytes without the witness length prefix, and the methods looking up public key hashes
/// return the public key.
///
/// This trait is automatically implemented for every type that is also a satisfier, and simply
/// proxies the queries to the satisfier and returns whether an item is available or not.
///
/// All the methods have a default implementation that returns `false` or `None`.
pub trait AssetProvider<Pk: MiniscriptKey> {
    /// Given the internal key, look up a key spend signature and return its size
    fn provider_lookup_tap_key_spend_sig(&self, _: &Pk) -> Option<usize> {
        None
    }

    /// Given a public key and an associated leaf hash, look up a Schnorr signature with that key
    /// and return its size
    fn provider_lookup_tap_leaf_script_sig(&self, _: &Pk, _: &TapLeafHash) -> Option<usize> {
        None
    }

    /// Given a raw `Pkh`, lookup corresponding [`bitcoin::secp256k1::XOnlyPublicKey`]
    fn provider_lookup_raw_pkh_x_only_pk(&self, _: &hash160::Hash) -> Option<XOnlyPublicKey> {
        None
    }

    /// Given a keyhash and a leaf hash, look up the Schnorr signature and the associated key.
    ///
    /// Returns the key and the signature size if a signature is found.
    fn provider_lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        _: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, usize)> {
        None
    }

    /// Given a SHA256 hash, look up its preimage, return whether we found it
    fn provider_lookup_sha256(&self, _: &Pk::Sha256) -> bool {
        false
    }

    /// Given a HASH256 hash, look up its preimage, return whether we found it
    fn provider_lookup_hash256(&self, _: &Pk::Hash256) -> bool {
        false
    }

    /// Given a RIPEMD160 hash, look up its preimage, return whether we found it
    fn provider_lookup_ripemd160(&self, _: &Pk::Ripemd160) -> bool {
        false
    }

    /// Given a HASH160 hash, look up its preimage, return whether we found it
    fn provider_lookup_hash160(&self, _: &Pk::Hash160) -> bool {
        false
    }

    /// Assert whether a relative locktime is satisfied
    fn check_older(&self, _: Sequence) -> bool {
        false
    }

    /// Assert whether an absolute locktime is satisfied
    fn check_after(&self, _: LockTime) -> bool {
        false
    }
}

fn schnorr_sig_len(sig: &SchnorrSig) -> usize {
    match sig.hash_ty {
        SchnorrSighashType::Default => 64,
        _ => 65,
    }
}

impl<T, Pk> AssetProvider<Pk> for T
where
    T: Satisfier<Pk>,
    Pk: MiniscriptKey + ToPublicKey,
{
    fn provider_lookup_tap_key_spend_sig(&self, _: &Pk) -> Option<usize> {
        Satisfier::<Pk>::lookup_tap_key_spend_sig(self).map(|sig| schnorr_sig_len(&sig))
    }

    fn provider_lookup_tap_leaf_script_sig(
        &self,
        pk: &Pk,
        leaf_hash: &TapLeafHash,
    ) -> Option<usize> {
        Satisfier::<Pk>::lookup_tap_leaf_script_sig(self, pk, leaf_hash)
            .map(|sig| schnorr_sig_len(&sig))
    }

    fn provider_lookup_raw_pkh_x_only_pk(&self, hash: &hash160::Hash) -> Option<XOnlyPublicKey> {
        Satisfier::<Pk>::lookup_raw_pkh_x_only_pk(self, hash)
    }

    fn provider_lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        hash: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, usize)> {
        Satisfier::<Pk>::lookup_raw_pkh_tap_leaf_script_sig(self, hash)
            .map(|(pk, sig)| (pk, schnorr_sig_len(&sig)))
    }

    fn provider_lookup_sha256(&self, hash: &Pk::Sha256) -> bool {
        Satisfier::<Pk>::lookup_sha256(self, hash).is_some()
    }

    fn provider_lookup_hash256(&self, hash: &Pk::Hash256) -> bool {
        Satisfier::<Pk>::lookup_hash256(self, hash).is_some()
    }

    fn provider_lookup_ripemd160(&self, hash: &Pk::Ripemd160) -> bool {
        Satisfier::<Pk>::lookup_ripemd160(self, hash).is_some()
    }

    fn provider_lookup_hash160(&self, hash: &Pk::Hash160) -> bool {
        Satisfier::<Pk>::lookup_hash160(self, hash).is_some()
    }

    fn check_older(&self, s: Sequence) -> bool {
        Satisfier::<Pk>::check_older(self, s)
    }

    fn check_after(&self, l: LockTime) -> bool {
        Satisfier::<Pk>::check_after(self, l)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Signatures which a Taproot key can produce
///
/// Defaults to `key_spend=true`, `script_spend=Any` and `sighash_default=true`
pub struct TaprootCanSign {
    /// Can produce key spend signatures
    pub key_spend: bool,
    /// Can produce script spend signatures
    pub script_spend: TaprootAvailableLeaves,
    /// Whether `SIGHASH_DEFAULT` will be used to sign
    pub sighash_default: bool,
}

impl TaprootCanSign {
    fn sig_len(&self) -> usize {
        match self.sighash_default {
            true => 64,
            false => 65,
        }
    }
}

impl Default for TaprootCanSign {
    fn default() -> Self {
        Self {
            key_spend: true,
            script_spend: TaprootAvailableLeaves::Any,
            sighash_default: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Which Taproot leaves the key can sign for
pub enum TaprootAvailableLeaves {
    /// Cannot sign for any leaf
    None,
    /// Can sign for any leaf
    Any,
    /// Can sign only for a specific leaf
    Single(TapLeafHash),
    /// Can sign for multiple leaves
    Many(Vec<TapLeafHash>),
}

impl TaprootAvailableLeaves {
    fn is_available(&self, lh: &TapLeafHash) -> bool {
        match self {
            TaprootAvailableLeaves::None => false,
            TaprootAvailableLeaves::Any => true,
            TaprootAvailableLeaves::Single(v) => v == lh,
            TaprootAvailableLeaves::Many(list) => list.contains(lh),
        }
    }
}

/// The assets we can use to satisfy a particular Taproot spending path
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Assets {
    /// Keys the user can sign for, and how.
    ///
    /// A pair `(fingerprint, derivation_path)` is
    /// provided, meaning that the user can sign using the key with `fingerprint`,
    /// derived with either `derivation_path` or a derivation path that extends `derivation_path`
    /// by exactly one child number. For example, if the derivation path `m/0/1` is provided, the
    /// user can sign with either `m/0/1` or `m/0/1/*`.
    pub keys: BTreeSet<(bip32::KeySource, TaprootCanSign)>,
    /// Set of available sha256 preimages
    pub sha256_preimages: BTreeSet<sha256::Hash>,
    /// Set of available hash256 preimages
    pub hash256_preimages: BTreeSet<hash256::Hash>,
    /// Set of available ripemd160 preimages
    pub ripemd160_preimages: BTreeSet<ripemd160::Hash>,
    /// Set of available hash160 preimages
    pub hash160_preimages: BTreeSet<hash160::Hash>,
    /// Maximum absolute timelock allowed
    pub absolute_timelock: Option<LockTime>,
    /// Maximum relative timelock allowed
    pub relative_timelock: Option<Sequence>,
}

// Checks if the `pk` is a "direct child" of the `derivation_path` provided.
// Direct child means that the key derivation path is either the same as the
// `derivation_path`, or the same extended by exactly one child number.
// For example, `pk/0/1/2` is a direct child of `m/0/1` and of `m/0/1/2`,
// but not of `m/0`.
fn is_key_direct_child_of(
    pk: &DefiniteDescriptorKey,
    derivation_path: &bip32::DerivationPath,
) -> bool {
    let pk_derivation_path = match pk.full_derivation_path() {
        Some(path) => path,
        None => return false,
    };
    let pk_path: &[bip32::ChildNumber] = pk_derivation_path.as_ref();
    let path: &[bip32::ChildNumber] = derivation_path.as_ref();
    pk_path == path || pk_path.split_last().map(|(_, parent)| parent) == Some(path)
}

impl Assets {
    // The size of a signature by `pk`, if one of the keys can sign for it as `can_sign` requires.
    fn sig_len(
        &self,
        pk: &DefiniteDescriptorKey,
        can_sign: impl Fn(&TaprootCanSign) -> bool,
    ) -> Option<usize> {
        self.keys.iter().find_map(|(keysource, taproot)| {
            if can_sign(taproot)
                && pk.master_fingerprint() == keysource.0
                && is_key_direct_child_of(pk, &keysource.1)
            {
                Some(taproot.sig_len())
            } else {
                None
            }
        })
    }
}

impl AssetProvider<DefiniteDescriptorKey> for Assets {
    fn provider_lookup_tap_key_spend_sig(&self, pk: &DefiniteDescriptorKey) -> Option<usize> {
        self.sig_len(pk, |taproot| taproot.key_spend)
    }

    fn provider_lookup_tap_leaf_script_sig(
        &self,
        pk: &DefiniteDescriptorKey,
        tap_leaf_hash: &TapLeafHash,
    ) -> Option<usize> {
        self.sig_len(pk, |taproot| {
            taproot.script_spend.is_available(tap_leaf_hash)
        })
    }

    fn provider_lookup_sha256(&self, hash: &sha256::Hash) -> bool {
        self.sha256_preimages.contains(hash)
    }

    fn provider_lookup_hash256(&self, hash: &hash256::Hash) -> bool {
        self.hash256_preimages.contains(hash)
    }

    fn provider_lookup_ripemd160(&self, hash: &ripemd160::Hash) -> bool {
        self.ripemd160_preimages.contains(hash)
    }

    fn provider_lookup_hash160(&self, hash: &hash160::Hash) -> bool {
        self.hash160_preimages.contains(hash)
    }

    fn check_older(&self, s: Sequence) -> bool {
        self.relative_timelock
            .is_some_and(|timelock| Satisfier::<DefiniteDescriptorKey>::check_older(&timelock, s))
    }

    fn check_after(&self, l: LockTime) -> bool {
        self.absolute_timelock
            .is_some_and(|timelock| Satisfier::<DefiniteDescriptorKey>::check_after(&timelock, l))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Type of schnorr signature to produce
pub enum SchnorrSigType {
    /// Key spend signature
    KeySpend {
        /// Merkle root to tweak the key, if present
        merkle_root: Option<TapNodeHash>,
    },
    /// Script spend signature
    ScriptSpend {
        /// Leaf hash of the script
        leaf_hash: TapLeafHash,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Placeholder for an item of a witness template
pub enum Placeholder<Pk: MiniscriptKey> {
    /// Public key
    Pubkey(Pk),
    /// Public key of a raw public key hash
    XOnlyPubkey(XOnlyPublicKey),
    /// Schnorr signature and its size, without the length prefix
    SchnorrSigPk(Pk, SchnorrSigType, usize),
    /// Schnorr signature given the pubkey hash, the tapleafhash, and the sig size, without the
    /// length prefix
    SchnorrSigPkHash(hash160::Hash, TapLeafHash, usize),
    /// SHA-256 preimage
    Sha256Preimage(Pk::Sha256),
    /// HASH256 preimage
    Hash256Preimage(Pk::Hash256),
    /// RIPEMD160 preimage
    Ripemd160Preimage(Pk::Ripemd160),
    /// HASH160 preimage
    Hash160Preimage(Pk::Hash160),
    /// Hash dissatisfaction (32 bytes of 0x00)
    HashDissatisfaction,
    /// OP_1
    PushOne,
    /// \<empty item\>
    PushZero,
    /// Taproot leaf script
    TapScript(Script),
    /// Taproot control block
    TapControlBlock(ControlBlock),
}

impl<Pk: MiniscriptKey> Placeholder<Pk> {
    // The size of the item in a serialized witness, with its length prefix.
    fn serialized_size(&self) -> usize {
        match self {
            Placeholder::Pubkey(pk) => Tap::pk_len(pk),
            Placeholder::XOnlyPubkey(pk) => Tap::pk_len(pk),
            Placeholder::SchnorrSigPk(_, _, size) | Placeholder::SchnorrSigPkHash(_, _, size) => {
                size + 1
            }
            Placeholder::HashDissatisfaction
            | Placeholder::Sha256Preimage(_)
            | Placeholder::Hash256Preimage(_)
            | Placeholder::Ripemd160Preimage(_)
            | Placeholder::Hash160Preimage(_) => 33,
            Placeholder::PushOne => 2,
            Placeholder::PushZero => 1,
            Placeholder::TapScript(s) => s.len() + varint_len(s.len()),
            Placeholder::TapControlBlock(cb) => cb.size() + varint_len(cb.size()),
        }
    }
}

// The size of the items of `stack` in a serialized witness, with their length prefixes but
// without the item count.
pub(crate) fn serialized_items_size<Pk: MiniscriptKey>(stack: &[Placeholder<Pk>]) -> usize {
    stack.iter().map(Placeholder::serialized_size).sum()
}

// The size of `stack` as a serialized witness.
fn serialized_witness_size<Pk: MiniscriptKey>(stack: &[Placeholder<Pk>]) -> usize {
    varint_len(stack.len()) + serialized_items_size(stack)
}

impl<Pk: MiniscriptKey + ToPublicKey> Placeholder<Pk> {
    /// Replaces the placeholder with the information given by the satisfier
    pub fn satisfy_self<Sat: Satisfier<Pk>>(&self, sat: &Sat) -> Option<Vec<u8>> {
        match self {
            Placeholder::Pubkey(pk) => Some(pk.to_x_only_pubkey().serialize().to_vec()),
            Placeholder::XOnlyPubkey(pk) => Some(pk.serialize().to_vec()),
            Placeholder::SchnorrSigPk(pk, SchnorrSigType::ScriptSpend { leaf_hash }, _) => sat
                .lookup_tap_leaf_script_sig(pk, leaf_hash)
                .map(|sig| sig.to_vec()),
            Placeholder::SchnorrSigPk(_, SchnorrSigType::KeySpend { .. }, _) => {
                sat.lookup_tap_key_spend_sig().map(|sig| sig.to_vec())
            }
            Placeholder::SchnorrSigPkHash(pkh, leaf_hash, _) => sat
                .lookup_raw_pkh_tap_leaf_script_sig(&(*pkh, *leaf_hash))
                .map(|(_, sig)| sig.to_vec()),
            Placeholder::Sha256Preimage(h) => sat.lookup_sha256(h).map(|p| p.to_vec()),
            Placeholder::Hash256Preimage(h) => sat.lookup_hash256(h).map(|p| p.to_vec()),
            Placeholder::Ripemd160Preimage(h) => sat.lookup_ripemd160(h).map(|p| p.to_vec()),
            Placeholder::Hash160Preimage(h) => sat.lookup_hash160(h).map(|p| p.to_vec()),
            Placeholder::HashDissatisfaction => Some(vec![0; 32]),
            Placeholder::PushZero => Some(vec![]),
            Placeholder::PushOne => Some(vec![1]),
            Placeholder::TapScript(s) => Some(s.to_bytes()),
            Placeholder::TapControlBlock(cb) => Some(cb.serialize()),
        }
    }
}

/// A witness, if available, for a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Witness<T> {
    /// Witness Available and the value of the witness
    Stack(Vec<T>),
    /// Third party can possibly satisfy the fragment but we cannot
    /// Witness Unavailable
    Unavailable,
    /// No third party can produce a satisfaction without private key
    /// Witness Impossible
    Impossible,
}

impl<Pk: MiniscriptKey> PartialOrd for Witness<Placeholder<Pk>> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Pk: MiniscriptKey> Ord for Witness<Placeholder<Pk>> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (Witness::Stack(v1), Witness::Stack(v2)) => {
                serialized_witness_size(v1).cmp(&serialized_witness_size(v2))
            }
            (Witness::Stack(_), _) => cmp::Ordering::Less,
            (_, Witness::Stack(_)) => cmp::Ordering::Greater,
            (Witness::Impossible, Witness::Unavailable) => cmp::Ordering::Less,
            (Witness::Unavailable, Witness::Impossible) => cmp::Ordering::Greater,
            (Witness::Impossible, Witness::Impossible) => cmp::Ordering::Equal,
            (Witness::Unavailable, Witness::Unavailable) => cmp::Ordering::Equal,
        }
    }
}

impl<T> Witness<T> {
    fn combine(one: Self, two: Self) -> Self {
        match (one, two) {
            (Witness::Impossible, _) | (_, Witness::Impossible) => Witness::Impossible,
            (Witness::Unavailable, _) | (_, Witness::Unavailable) => Witness::Unavailable,
            (Witness::Stack(mut a), Witness::Stack(b)) => {
                a.extend(b);
                Witness::Stack(a)
            }
        }
    }
}

impl<Pk: MiniscriptKey> Witness<Placeholder<Pk>> {
    fn hash_dissatisfaction() -> Self {
        Witness::Stack(vec![Placeholder::HashDissatisfaction])
    }

    fn push_1() -> Self {
        Witness::Stack(vec![Placeholder::PushOne])
    }

    fn push_0() -> Self {
        Witness::Stack(vec![Placeholder::PushZero])
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Witness<Placeholder<Pk>> {
    fn signature<P: AssetProvider<Pk>>(provider: &P, pk: &Pk, leaf_hash: &TapLeafHash) -> Self {
        match provider.provider_lookup_tap_leaf_script_sig(pk, leaf_hash) {
            Some(size) => Witness::Stack(vec![Placeholder::SchnorrSigPk(
                pk.clone(),
                SchnorrSigType::ScriptSpend {
                    leaf_hash: *leaf_hash,
                },
                size,
            )]),
            // Signatures cannot be forged
            None => Witness::Impossible,
        }
    }

    fn pkh_public_key<P: AssetProvider<Pk>>(provider: &P, pkh: &hash160::Hash) -> Self {
        match provider.provider_lookup_raw_pkh_x_only_pk(pkh) {
            Some(pk) => Witness::Stack(vec![Placeholder::XOnlyPubkey(pk)]),
            // A third party may know the public key, so it is unavailable, not impossible
            None => Witness::Unavailable,
        }
    }

    fn pkh_signature<P: AssetProvider<Pk>>(
        provider: &P,
        pkh: &hash160::Hash,
        leaf_hash: &TapLeafHash,
    ) -> Self {
        match provider.provider_lookup_raw_pkh_tap_leaf_script_sig(&(*pkh, *leaf_hash)) {
            Some((pk, size)) => Witness::Stack(vec![
                Placeholder::SchnorrSigPkHash(*pkh, *leaf_hash, size),
                Placeholder::XOnlyPubkey(pk),
            ]),
            None => Witness::Impossible,
        }
    }
}

/// A (dis)satisfaction of a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Satisfaction<T> {
    /// The actual witness stack
    pub stack: Witness<T>,
    /// Whether or not this (dis)satisfaction has a signature somewhere
    /// in it
    pub has_sig: bool,
    /// The absolute timelock used by this satisfaction
    pub absolute_timelock: Option<AbsLockTime>,
    /// The relative timelock used by this satisfaction
    pub relative_timelock: Option<Sequence>,
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfaction<Placeholder<Pk>> {
    const IMPOSSIBLE: Self = Self {
        stack: Witness::Impossible,
        has_sig: false,
        absolute_timelock: None,
        relative_timelock: None,
    };

    pub(crate) const UNAVAILABLE: Self = Self {
        stack: Witness::Unavailable,
        has_sig: false,
        absolute_timelock: None,
        relative_timelock: None,
    };

    fn from_stack(stack: Witness<Placeholder<Pk>>) -> Self {
        Self {
            stack,
            has_sig: false,
            absolute_timelock: None,
            relative_timelock: None,
        }
    }

    fn empty() -> Self {
        Self::from_stack(Witness::Stack(vec![]))
    }

    /// A hash preimage, which is unavailable instead of impossible when missing
    fn preimage(available: bool, preimage: Placeholder<Pk>) -> Self {
        Self::from_stack(if available {
            Witness::Stack(vec![preimage])
        } else {
            Witness::Unavailable
        })
    }

    /// Combines two satisfactions, the stack of `one` before that of `two`.
    ///
    /// Timelocks of the same unit merge to the later one. No transaction can
    /// satisfy timelocks of different units, so combining them is impossible.
    fn combine(one: Self, two: Self) -> Self {
        if matches!(one.stack, Witness::Impossible) || matches!(two.stack, Witness::Impossible) {
            return Self::IMPOSSIBLE;
        }
        // A timelock satisfies the timelocks of the same unit that are not later.
        let absolute_timelock = match (one.absolute_timelock, two.absolute_timelock) {
            (Some(a), Some(b)) => {
                if Satisfier::<Pk>::check_after(&LockTime::from(a), b.into()) {
                    Some(a)
                } else if Satisfier::<Pk>::check_after(&LockTime::from(b), a.into()) {
                    Some(b)
                } else {
                    return Self::IMPOSSIBLE;
                }
            }
            (a, b) => a.or(b),
        };
        let relative_timelock = match (one.relative_timelock, two.relative_timelock) {
            (Some(a), Some(b)) => {
                if Satisfier::<Pk>::check_older(&a, b) {
                    Some(a)
                } else if Satisfier::<Pk>::check_older(&b, a) {
                    Some(b)
                } else {
                    return Self::IMPOSSIBLE;
                }
            }
            (a, b) => a.or(b),
        };
        Self {
            stack: Witness::combine(one.stack, two.stack),
            has_sig: one.has_sig || two.has_sig,
            absolute_timelock,
            relative_timelock,
        }
    }

    fn thresh(k: usize, dissats: Vec<Self>, mut sats: Vec<Self>) -> Self {
        let mut ret_stack = dissats;

        // Sort everything by (sat cost - dissat cost), except that
        // satisfactions without signatures beat satisfactions with
        // signatures
        let mut sat_indices = (0..sats.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| {
            let stack_weight = match (&sats[i].stack, &ret_stack[i].stack) {
                (&Witness::Unavailable, _) | (&Witness::Impossible, _) => i64::MAX,
                (_, &Witness::Unavailable) | (_, &Witness::Impossible) => i64::MIN,
                (Witness::Stack(s), Witness::Stack(d)) => {
                    serialized_witness_size(s) as i64 - serialized_witness_size(d) as i64
                }
            };
            let is_impossible = matches!(sats[i].stack, Witness::Impossible);
            // First consider the candidates that are not impossible to satisfy
            // by any party. Among those first consider the ones that have no sig
            // because third party can malleate them if they are not chosen.
            // Lastly, choose by weight.
            (is_impossible, sats[i].has_sig, stack_weight)
        });

        for &i in &sat_indices[..k] {
            mem::swap(&mut ret_stack[i], &mut sats[i]);
        }

        // We preferably take satisfactions that are not impossible
        // If we cannot find `k` satisfactions that are not impossible
        // then the threshold branch is impossible to satisfy
        // For example, the fragment thresh(2, hash, 0, 0, 0)
        // has an impossible witness
        if matches!(sats[sat_indices[k - 1]].stack, Witness::Impossible) {
            Self::IMPOSSIBLE
        }
        // We are now guaranteed that all elements in `k` satisfactions
        // are not impossible(we sort by is_impossible bool).
        // The above loop should have taken everything without a sig
        // (since those were sorted higher than non-sigs). If there
        // are remaining non-sig satisfactions this indicates a
        // malleability vector
        // For example, the fragment thresh(2, hash, hash, 0, 0)
        // is uniquely satisfiable because there is no satisfaction
        // for the 0 fragment
        else if k < sat_indices.len()
            && !sats[sat_indices[k]].has_sig
            && !matches!(sats[sat_indices[k]].stack, Witness::Impossible)
        {
            // All arguments should be `d`, so dissatisfactions have no
            // signatures; and in this branch we assume too many weak
            // arguments, so none of the satisfactions should have
            // signatures either.
            for sat in &ret_stack {
                assert!(!sat.has_sig);
            }
            Self::UNAVAILABLE
        } else {
            ret_stack
                .into_iter()
                .fold(Self::empty(), |acc, next| Self::combine(next, acc))
        }
    }

    fn thresh_mall(k: usize, dissats: Vec<Self>, mut sats: Vec<Self>) -> Self {
        let mut ret_stack = dissats;

        // For malleable satisfactions, directly choose smallest weights
        let mut sat_indices = (0..sats.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| match (&sats[i].stack, &ret_stack[i].stack) {
            (&Witness::Unavailable, _) | (&Witness::Impossible, _) => i64::MAX,
            (_, &Witness::Unavailable) | (_, &Witness::Impossible) => i64::MIN,
            (Witness::Stack(s), Witness::Stack(d)) => {
                serialized_witness_size(s) as i64 - serialized_witness_size(d) as i64
            }
        });

        for &i in &sat_indices[..k] {
            mem::swap(&mut ret_stack[i], &mut sats[i]);
        }

        ret_stack
            .into_iter()
            .fold(Self::empty(), |acc, next| Self::combine(next, acc))
    }

    fn minimum(sat1: Self, sat2: Self) -> Self {
        // If there is only one available satisfaction, we must choose that
        // regardless of has_sig marker.
        // This handles the case where both are impossible.
        match (&sat1.stack, &sat2.stack) {
            (&Witness::Impossible, _) => return sat2,
            (_, &Witness::Impossible) => return sat1,
            _ => {}
        }
        match (sat1.has_sig, sat2.has_sig) {
            // If neither option has a signature, this is a malleability
            // vector, so choose neither one.
            (false, false) => Self::UNAVAILABLE,
            // If only one has a signature, take the one that doesn't; a
            // third party could malleate by removing the signature, but
            // can't malleate if he'd have to add it
            (false, true) => sat1,
            (true, false) => sat2,
            // If both have a signature associated with them, choose the
            // cheaper one (where "cheaper" is defined such that available
            // things are cheaper than unavailable ones)
            (true, true) if sat2.stack < sat1.stack => sat2,
            (true, true) => sat1,
        }
    }

    fn minimum_mall(sat1: Self, sat2: Self) -> Self {
        match (&sat1.stack, &sat2.stack) {
            // If there is only one possible satisfaction, use it regardless
            // of the other one
            (&Witness::Impossible, _) | (&Witness::Unavailable, _) => return sat2,
            (_, &Witness::Impossible) | (_, &Witness::Unavailable) => return sat1,
            _ => {}
        }
        let has_sig = sat1.has_sig && sat2.has_sig;
        let min = if sat2.stack < sat1.stack { sat2 } else { sat1 };
        Self { has_sig, ..min }
    }

    /// Computes the satisfaction and the dissatisfaction of a Tapscript fragment, in this
    /// order, from those of its children, which are on top of `stack`, first child on top.
    fn sat_dissat<P, Ext>(
        term: &Terminal<Pk, Tap, Ext>,
        stack: &mut Vec<(Self, Self)>,
        provider: &P,
        mall: bool,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
    ) -> (Self, Self)
    where
        P: AssetProvider<Pk>,
        Ext: Extension,
    {
        let min_fn = if mall {
            Self::minimum_mall
        } else {
            Self::minimum
        };
        let mut child = || {
            stack
                .pop()
                .expect("children are evaluated before their parent")
        };

        match *term {
            Terminal::True => (Self::empty(), Self::IMPOSSIBLE),
            Terminal::False => (Self::IMPOSSIBLE, Self::empty()),
            Terminal::PkK(ref pk) => (
                Self {
                    has_sig: true,
                    ..Self::from_stack(Witness::signature(provider, pk, leaf_hash))
                },
                Self::from_stack(Witness::push_0()),
            ),
            Terminal::PkH(ref pk) => {
                let pk_push = || Witness::Stack(vec![Placeholder::Pubkey(pk.clone())]);
                (
                    Self {
                        has_sig: true,
                        ..Self::from_stack(Witness::combine(
                            Witness::signature(provider, pk, leaf_hash),
                            pk_push(),
                        ))
                    },
                    Self::from_stack(Witness::combine(Witness::push_0(), pk_push())),
                )
            }
            Terminal::RawPkH(ref pkh) => (
                Self {
                    has_sig: true,
                    ..Self::from_stack(Witness::pkh_signature(provider, pkh, leaf_hash))
                },
                Self::from_stack(Witness::combine(
                    Witness::push_0(),
                    Witness::pkh_public_key(provider, pkh),
                )),
            ),
            Terminal::After(t) => {
                let sat = if provider.check_after(t.into()) {
                    Self {
                        absolute_timelock: Some(t),
                        ..Self::empty()
                    }
                } else if root_has_sig {
                    // If the root terminal has signature, the
                    // signature covers the nLockTime and nSequence
                    // values. The sender of the transaction should
                    // take care that it signs the value such that the
                    // timelock is not met
                    Self::IMPOSSIBLE
                } else {
                    Self::UNAVAILABLE
                };
                (sat, Self::IMPOSSIBLE)
            }
            Terminal::Older(t) => {
                let sat = if provider.check_older(t) {
                    Self {
                        relative_timelock: Some(t),
                        ..Self::empty()
                    }
                } else if root_has_sig {
                    // See the comment for `After` above
                    Self::IMPOSSIBLE
                } else {
                    Self::UNAVAILABLE
                };
                (sat, Self::IMPOSSIBLE)
            }
            Terminal::Sha256(ref h) => (
                Self::preimage(
                    provider.provider_lookup_sha256(h),
                    Placeholder::Sha256Preimage(h.clone()),
                ),
                Self::from_stack(Witness::hash_dissatisfaction()),
            ),
            Terminal::Hash256(ref h) => (
                Self::preimage(
                    provider.provider_lookup_hash256(h),
                    Placeholder::Hash256Preimage(h.clone()),
                ),
                Self::from_stack(Witness::hash_dissatisfaction()),
            ),
            Terminal::Ripemd160(ref h) => (
                Self::preimage(
                    provider.provider_lookup_ripemd160(h),
                    Placeholder::Ripemd160Preimage(h.clone()),
                ),
                Self::from_stack(Witness::hash_dissatisfaction()),
            ),
            Terminal::Hash160(ref h) => (
                Self::preimage(
                    provider.provider_lookup_hash160(h),
                    Placeholder::Hash160Preimage(h.clone()),
                ),
                Self::from_stack(Witness::hash_dissatisfaction()),
            ),
            Terminal::Alt(_)
            | Terminal::Swap(_)
            | Terminal::Check(_)
            | Terminal::ZeroNotEqual(_) => child(),
            Terminal::DupIf(_) => {
                let (sat, _) = child();
                (
                    Self::combine(sat, Self::from_stack(Witness::push_1())),
                    Self::from_stack(Witness::push_0()),
                )
            }
            Terminal::Verify(_) => (child().0, Self::IMPOSSIBLE),
            Terminal::NonZero(_) => (child().0, Self::from_stack(Witness::push_0())),
            Terminal::AndV(..) => {
                let (l_sat, _) = child();
                let (r_sat, r_dissat) = child();
                (
                    Self::combine(r_sat, l_sat.clone()),
                    Self::combine(r_dissat, l_sat),
                )
            }
            Terminal::AndB(..) => {
                let (l_sat, l_dissat) = child();
                let (r_sat, r_dissat) = child();
                (
                    Self::combine(r_sat, l_sat),
                    Self::combine(r_dissat, l_dissat),
                )
            }
            Terminal::AndOr(..) => {
                let (a_sat, a_dissat) = child();
                let (b_sat, _) = child();
                let (c_sat, c_dissat) = child();
                (
                    min_fn(
                        Self::combine(b_sat, a_sat),
                        Self::combine(c_sat, a_dissat.clone()),
                    ),
                    Self::combine(c_dissat, a_dissat),
                )
            }
            Terminal::OrB(..) => {
                let (l_sat, l_dissat) = child();
                let (r_sat, r_dissat) = child();
                assert!(!l_dissat.has_sig);
                assert!(!r_dissat.has_sig);
                (
                    min_fn(
                        Self::combine(r_sat, l_dissat.clone()),
                        Self::combine(r_dissat.clone(), l_sat),
                    ),
                    Self::combine(r_dissat, l_dissat),
                )
            }
            Terminal::OrD(..) => {
                let (l_sat, l_dissat) = child();
                let (r_sat, r_dissat) = child();
                assert!(!l_dissat.has_sig);
                (
                    min_fn(l_sat, Self::combine(r_sat, l_dissat.clone())),
                    Self::combine(r_dissat, l_dissat),
                )
            }
            Terminal::OrC(..) => {
                let (l_sat, l_dissat) = child();
                let (r_sat, _) = child();
                assert!(!l_dissat.has_sig);
                (
                    min_fn(l_sat, Self::combine(r_sat, l_dissat)),
                    Self::IMPOSSIBLE,
                )
            }
            Terminal::OrI(..) => {
                let (l_sat, l_dissat) = child();
                let (r_sat, r_dissat) = child();
                let left = |s| Self::combine(s, Self::from_stack(Witness::push_1()));
                let right = |s| Self::combine(s, Self::from_stack(Witness::push_0()));
                (
                    min_fn(left(l_sat), right(r_sat)),
                    // Dissatisfactions don't need to be non-malleable. Use minimum_mall always
                    Self::minimum_mall(left(l_dissat), right(r_dissat)),
                )
            }
            Terminal::Thresh(k, ref subs) => {
                let (sats, dissats): (Vec<_>, Vec<_>) = subs.iter().map(|_| child()).unzip();
                let dissat = dissats
                    .iter()
                    .cloned()
                    .fold(Self::empty(), |acc, next| Self::combine(next, acc));
                let sat = if mall {
                    Self::thresh_mall(k, dissats, sats)
                } else {
                    Self::thresh(k, dissats, sats)
                };
                (sat, dissat)
            }
            // `multi` is disabled in Tapscript.
            Terminal::Multi(..) => (Self::IMPOSSIBLE, Self::IMPOSSIBLE),
            Terminal::MultiA(k, ref keys) => {
                let dissat = vec![Placeholder::PushZero; keys.len()];
                // The witness has an item for every key, the last key first.
                let sigs: Vec<_> = keys
                    .iter()
                    .rev()
                    .enumerate()
                    .filter_map(|(i, pk)| {
                        let size = provider.provider_lookup_tap_leaf_script_sig(pk, leaf_hash)?;
                        Some((i, pk, size))
                    })
                    .collect();
                let sat = if sigs.len() < k {
                    Self::IMPOSSIBLE
                } else {
                    // The `k` smallest signatures: 64-byte signatures before 65-byte ones, the
                    // last keys first among signatures of the same size.
                    let short = sigs.iter().filter(|&&(_, _, size)| size == 64);
                    let long = sigs.iter().filter(|&&(_, _, size)| size != 64);
                    let mut items = dissat.clone();
                    for &(i, pk, size) in short.chain(long).take(k) {
                        let sig_type = SchnorrSigType::ScriptSpend {
                            leaf_hash: *leaf_hash,
                        };
                        items[i] = Placeholder::SchnorrSigPk(pk.clone(), sig_type, size);
                    }
                    Self {
                        has_sig: true,
                        ..Self::from_stack(Witness::Stack(items))
                    }
                };
                (sat, Self::from_stack(Witness::Stack(dissat)))
            }
            Terminal::Ext(_) => (Self::UNAVAILABLE, Self::UNAVAILABLE),
        }
    }

    /// Builds the template of a Tapscript leaf with the given leaf hash
    pub(crate) fn build_template<P, Ext>(
        ms: &Miniscript<Pk, Tap, Ext>,
        provider: &P,
        mall: bool,
        leaf_hash: &TapLeafHash,
    ) -> Self
    where
        P: AssetProvider<Pk>,
        Ext: Extension,
    {
        // Without recursion: in reverse pre-order every fragment comes after its descendants.
        let fragments: Vec<_> = ms.iter().collect();
        let mut stack = Vec::new();
        for fragment in fragments.into_iter().rev() {
            let sat_dissat = Self::sat_dissat(
                &fragment.node,
                &mut stack,
                provider,
                mall,
                ms.ty.mall.safe,
                leaf_hash,
            );
            stack.push(sat_dissat);
        }
        let (sat, _) = stack.pop().expect("the root is evaluated last");
        sat
    }

    /// The size of the witness of the template when serialized, including its item count and
    /// the length prefix of every item, or `None` if the template has no stack.
    ///
    /// Script-path templates of [`Tr::plan_satisfaction`] and [`Tr::plan_satisfaction_mall`]
    /// include the leaf script and control block. Leaf templates from
    /// [`Miniscript::build_template`] exclude them. Signature sizes are those declared by the
    /// [`AssetProvider`] that built the template.
    ///
    /// [`Tr::plan_satisfaction`]: crate::descriptor::Tr::plan_satisfaction
    /// [`Tr::plan_satisfaction_mall`]: crate::descriptor::Tr::plan_satisfaction_mall
    pub fn witness_size(&self) -> Option<usize> {
        match self.stack {
            Witness::Stack(ref stack) => Some(serialized_witness_size(stack)),
            Witness::Unavailable | Witness::Impossible => None,
        }
    }

    /// Try creating the final witness using a [`Satisfier`]
    ///
    /// Returns `None` if the satisfier lacks an item of the stack. An unavailable or impossible
    /// template is returned in `Some` unchanged. The timelocks of the template are carried
    /// over without checking them: the spending transaction must satisfy them.
    pub fn try_completing<Sat: Satisfier<Pk>>(&self, stfr: &Sat) -> Option<Satisfaction<Vec<u8>>> {
        let stack = match self.stack {
            Witness::Stack(ref stack) => Witness::Stack(
                stack
                    .iter()
                    .map(|placeholder| placeholder.satisfy_self(stfr))
                    .collect::<Option<_>>()?,
            ),
            Witness::Unavailable => Witness::Unavailable,
            Witness::Impossible => Witness::Impossible,
        };
        Some(Satisfaction {
            stack,
            has_sig: self.has_sig,
            absolute_timelock: self.absolute_timelock,
            relative_timelock: self.relative_timelock,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::hashes::Hash;
    use elements::secp256k1_zkp::schnorr;
    use elements::taproot::LeafVersion;

    use super::*;
    use crate::descriptor::{DescriptorPublicKey, Tr};

    const KEYS: [&str; 5] = [
        "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
        "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
        "03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5",
        "033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9",
        "023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4",
    ];

    // Assets to sign with `keys`.
    fn signing_assets(keys: &[&DescriptorPublicKey]) -> Assets {
        Assets {
            keys: keys
                .iter()
                .map(|key| {
                    let key_source = (
                        key.master_fingerprint(),
                        key.full_derivation_path().unwrap(),
                    );
                    (key_source, TaprootCanSign::default())
                })
                .collect(),
            ..Default::default()
        }
    }

    // A signature by `key` for every leaf of `tr`.
    fn signatures(
        tr: &Tr<DefiniteDescriptorKey>,
        key: &DescriptorPublicKey,
    ) -> HashMap<(DefiniteDescriptorKey, TapLeafHash), SchnorrSig> {
        let key = DefiniteDescriptorKey::from_str(&key.to_string()).unwrap();
        let sig = SchnorrSig {
            sig: schnorr::Signature::from_str("84526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f0784526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07").unwrap(),
            hash_ty: SchnorrSighashType::Default,
        };
        tr.spend_info()
            .leaves()
            .map(|leaf| ((key.clone(), leaf.leaf_hash()), sig))
            .collect()
    }

    #[test]
    fn plan_taproot() {
        let keys = KEYS.map(|key| DescriptorPublicKey::from_str(key).unwrap());
        // A = pk(key1) at depth 1, B = multi_a(1,key2,key3) and C = and_v(v:pk(key4),after(10))
        // at depth 2.
        let desc = format!(
            "eltr({},{{pk({}),{{multi_a(1,{},{}),and_v(v:pk({}),after(10))}}}})",
            keys[0], keys[1], keys[2], keys[3], keys[4]
        );
        let tr = Tr::<DefiniteDescriptorKey>::from_str(&desc).unwrap();
        let assets = |key_indexes: &[usize], absolute_timelock| Assets {
            absolute_timelock,
            ..signing_assets(&key_indexes.iter().map(|&i| &keys[i]).collect::<Vec<_>>())
        };
        let height = |n| Some(LockTime::from_consensus(n));

        // Witness sizes: the item count, then each item with its length prefix.
        // Key spend: 1 + (1 + 64)
        let key_spend = Some(66);
        // A: 1 + (1 + 64) + (1 + 34) + (1 + 65)
        let first_leaf = Some(167);
        // B: 1 + 1 + (1 + 64) + (1 + 70) + (1 + 97)
        let second_leaf = Some(236);
        // C: 1 + (1 + 64) + (1 + 36) + (1 + 97)
        let third_leaf = Some(201);
        let tests: [(&[usize], Option<LockTime>, Option<usize>); 13] = [
            // Don't give assets
            (&[], None, None),
            // Spend with internal key
            (&[0], None, key_spend),
            // Spend with first leaf (single pk)
            (&[1], None, first_leaf),
            // Spend with second leaf (1of2)
            (&[2], None, second_leaf),
            (&[2, 3], None, second_leaf),
            // Spend with third leaf (key + timelock)
            (&[4], height(10), third_leaf),
            // ... but the timelock is too low
            (&[4], height(9), None),
            // ... in the wrong unit
            (&[4], Some(LockTime::from_consensus(1296000000)), None),
            // ... or not given
            (&[4], None, None),
            // Give all the keys (internal key will be used, as it's cheaper)
            (&[0, 1, 2, 3, 4], None, key_spend),
            // Give all the leaf keys (uses 1st leaf)
            (&[1, 2, 3, 4], None, first_leaf),
            // Give 2nd+3rd leaf without timelock (uses 2nd leaf)
            (&[2, 3, 4], None, second_leaf),
            // Give 2nd+3rd leaf with timelock (uses 3rd leaf)
            (&[2, 3, 4], height(11), third_leaf),
        ];
        for (key_indexes, absolute_timelock, expected) in tests {
            let plan = tr.plan_satisfaction(&assets(key_indexes, absolute_timelock));
            assert_eq!(
                plan.witness_size(),
                expected,
                "{:?}, {:?}",
                key_indexes,
                absolute_timelock
            );
            let timelock = if expected == third_leaf {
                Some(AbsLockTime::from_consensus(10))
            } else {
                None
            };
            assert_eq!(plan.absolute_timelock, timelock);
        }

        // The plan is made without signatures and completed once they exist.
        let plan = tr.plan_satisfaction(&assets(&[2, 3, 4], height(11)));
        let satisfier = (signatures(&tr, &keys[4]), LockTime::from_consensus(11));
        let (witness, _) = tr.get_satisfaction(&satisfier).unwrap();
        let completed = plan.try_completing(&satisfier).unwrap();
        assert_eq!(completed.stack, Witness::Stack(witness));
    }

    #[test]
    fn plan_hash_and_relative_timelock() {
        struct Preimage([u8; 32]);

        impl Satisfier<DefiniteDescriptorKey> for Preimage {
            fn lookup_sha256(&self, hash: &sha256::Hash) -> Option<[u8; 32]> {
                if sha256::Hash::hash(&self.0) == *hash {
                    Some(self.0)
                } else {
                    None
                }
            }
        }

        let keys = KEYS.map(|key| DescriptorPublicKey::from_str(key).unwrap());
        let preimage = [42; 32];
        let hash = sha256::Hash::hash(&preimage);
        let desc = format!(
            "eltr({},{{and_v(v:pk({}),sha256({})),and_v(v:pk({}),older(10))}})",
            keys[0], keys[1], hash, keys[2]
        );
        let tr = Tr::<DefiniteDescriptorKey>::from_str(&desc).unwrap();

        // The first leaf needs the preimage when planning,
        let assets = signing_assets(&[&keys[1]]);
        assert_eq!(tr.plan_satisfaction(&assets).witness_size(), None);
        let plan = tr.plan_satisfaction(&Assets {
            sha256_preimages: BTreeSet::from([hash]),
            ..assets
        });
        // and when completing.
        let sigs = signatures(&tr, &keys[1]);
        assert_eq!(plan.try_completing(&sigs), None);
        let satisfier = (sigs, Preimage(preimage));
        let (witness, _) = tr.get_satisfaction(&satisfier).unwrap();
        let completed = plan.try_completing(&satisfier).unwrap();
        assert_eq!(completed.stack, Witness::Stack(witness));

        // The second leaf needs a relative timelock of the same unit that is not shorter.
        for (relative_timelock, available) in [(10, true), (9, false), (0x0040_000a, false)] {
            let plan = tr.plan_satisfaction(&Assets {
                relative_timelock: Some(Sequence::from_consensus(relative_timelock)),
                ..signing_assets(&[&keys[2]])
            });
            let expected = if available {
                Some(Sequence::from_consensus(10))
            } else {
                None
            };
            assert_eq!(plan.relative_timelock, expected, "{:#x}", relative_timelock);
            assert_eq!(plan.witness_size().is_some(), available);
        }
    }

    #[test]
    fn plan_malleable_only() {
        struct Preimages;

        impl AssetProvider<bitcoin::PublicKey> for Preimages {
            fn provider_lookup_sha256(&self, _: &sha256::Hash) -> bool {
                true
            }
        }

        let [h1, h2] = [[1u8; 32], [2; 32]].map(|preimage| sha256::Hash::hash(&preimage));
        // A third party knowing both preimages can satisfy either branch.
        let ms = Miniscript::<bitcoin::PublicKey, Tap>::from_str_insane(&format!(
            "or_i(sha256({}),sha256({}))",
            h1, h2
        ))
        .unwrap();
        assert_eq!(ms.build_template(&Preimages).stack, Witness::Unavailable);
        assert_eq!(
            ms.build_template_mall(&Preimages).stack,
            Witness::Stack(vec![Placeholder::Sha256Preimage(h2), Placeholder::PushZero])
        );
    }

    #[test]
    fn multi_a_smallest_signatures() {
        struct SignatureSizes(Vec<(bitcoin::PublicKey, usize)>);

        impl AssetProvider<bitcoin::PublicKey> for SignatureSizes {
            fn provider_lookup_tap_leaf_script_sig(
                &self,
                pk: &bitcoin::PublicKey,
                _: &TapLeafHash,
            ) -> Option<usize> {
                self.0
                    .iter()
                    .find(|(key, _)| key == pk)
                    .map(|&(_, size)| size)
            }
        }

        let [a, b, c] =
            [KEYS[0], KEYS[1], KEYS[2]].map(|key| bitcoin::PublicKey::from_str(key).unwrap());
        let ms = Miniscript::<bitcoin::PublicKey, Tap>::from_str(&format!(
            "multi_a(2,{},{},{})",
            a, b, c
        ))
        .unwrap();
        let leaf_hash = TapLeafHash::from_script(&ms.encode(), LeafVersion::default());
        let sig = |pk, size| {
            Placeholder::SchnorrSigPk(pk, SchnorrSigType::ScriptSpend { leaf_hash }, size)
        };
        // The witness has the items of C, B and A in this order.
        for ([a_size, b_size, c_size], expected) in [
            // The shorter signature of A is used instead of that of B,
            (
                [64, 65, 65],
                vec![sig(c, 65), Placeholder::PushZero, sig(a, 64)],
            ),
            // and among signatures of the same size, those of the last keys.
            (
                [64, 64, 64],
                vec![sig(c, 64), sig(b, 64), Placeholder::PushZero],
            ),
        ] {
            let sizes = SignatureSizes(vec![(a, a_size), (b, b_size), (c, c_size)]);
            for template in [ms.build_template(&sizes), ms.build_template_mall(&sizes)] {
                assert_eq!(template.stack, Witness::Stack(expected.clone()));
            }
        }
    }

    #[test]
    fn assets_keys() {
        let key = DefiniteDescriptorKey::from_str("[d34db33f/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/1").unwrap();
        let assets = |path: &str, can_sign: TaprootCanSign| Assets {
            keys: BTreeSet::from([(
                (
                    key.master_fingerprint(),
                    bip32::DerivationPath::from_str(path).unwrap(),
                ),
                can_sign,
            )]),
            ..Default::default()
        };
        let leaf_hash = TapLeafHash::from_script(&Script::new(), LeafVersion::default());

        // The key or its parent can sign
        for path in ["m/86'/0'/0'/0/1", "m/86'/0'/0'/0"] {
            let assets = assets(path, TaprootCanSign::default());
            assert_eq!(assets.provider_lookup_tap_key_spend_sig(&key), Some(64));
            assert_eq!(
                assets.provider_lookup_tap_leaf_script_sig(&key, &leaf_hash),
                Some(64)
            );
        }
        // but no other ancestor or a sibling
        for path in ["m/86'/0'/0'", "m/86'/0'/0'/1"] {
            let assets = assets(path, TaprootCanSign::default());
            assert_eq!(assets.provider_lookup_tap_key_spend_sig(&key), None);
        }

        let can_sign = TaprootCanSign {
            key_spend: false,
            script_spend: TaprootAvailableLeaves::Single(leaf_hash),
            sighash_default: false,
        };
        let assets = assets("m/86'/0'/0'/0", can_sign);
        assert_eq!(assets.provider_lookup_tap_key_spend_sig(&key), None);
        assert_eq!(
            assets.provider_lookup_tap_leaf_script_sig(&key, &leaf_hash),
            Some(65)
        );
        let other_script = Script::from(vec![1]);
        let other_leaf_hash = TapLeafHash::from_script(&other_script, LeafVersion::default());
        assert_eq!(
            assets.provider_lookup_tap_leaf_script_sig(&key, &other_leaf_hash),
            None
        );
    }

    #[test]
    fn template_timelocks() {
        struct AllTimelocks;

        impl AssetProvider<bitcoin::PublicKey> for AllTimelocks {
            fn check_older(&self, _: Sequence) -> bool {
                true
            }

            fn check_after(&self, _: LockTime) -> bool {
                true
            }
        }

        let template = |ms: &str| {
            Miniscript::<bitcoin::PublicKey, Tap>::from_str_insane(ms)
                .unwrap()
                .build_template(&AllTimelocks)
        };

        // Timelocks of the same unit merge to the later one,
        let both = template("and_v(v:after(10),after(20))");
        assert_eq!(both.stack, Witness::Stack(vec![]));
        assert_eq!(
            both.absolute_timelock,
            Some(AbsLockTime::from_consensus(20))
        );
        let both = template("and_v(v:older(10),older(20))");
        assert_eq!(both.stack, Witness::Stack(vec![]));
        assert_eq!(both.relative_timelock, Some(Sequence::from_consensus(20)));
        // and no transaction satisfies timelocks of different units.
        let mixed = template("and_v(v:after(10),after(500000001))");
        assert_eq!(mixed.stack, Witness::Impossible);
        let mixed = template("and_v(v:older(10),older(4194305))");
        assert_eq!(mixed.stack, Witness::Impossible);
    }
}
