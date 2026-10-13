// SPDX-License-Identifier: CC0-1.0

//! Assets available for Taproot signing.

use std::collections::BTreeSet;

use bitcoin::bip32;
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::secp256k1::XOnlyPublicKey;
use elements::taproot::TapLeafHash;
use elements::{LockTime, SchnorrSig, SchnorrSighashType, Sequence};

use crate::{hash256, DefiniteDescriptorKey, MiniscriptKey, Satisfier, ToPublicKey};

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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elements::taproot::LeafVersion;
    use elements::Script;

    use super::*;
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
}
