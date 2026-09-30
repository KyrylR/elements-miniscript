#![cfg(feature = "simplicity")]
use std::str::FromStr;

use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements_miniscript::descriptor::Tr;
use elements_miniscript::policy::Liftable;
use elements_miniscript::{
    simplicity_lang as simplicity, Descriptor, DescriptorPublicKey, ForEachKey, SimplicityLeaf,
};
use simplicity::Cmr;

const KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

const CMR: &str = "0526eb603a8936dba018b14794dee96a87a6fd76987dd867c3e5a1773932fdfe";

#[test]
fn commitment_grammar_and_normalization() {
    let text = format!("sim{{asm({})}}", CMR);
    let leaf = SimplicityLeaf::from_str(&text).unwrap();
    assert_eq!(leaf.to_string(), text);
    assert_eq!(leaf.cmr(), Cmr::from_str(CMR).unwrap());
    assert_eq!(
        SimplicityLeaf::from_str(&format!("sim{{asm({})}}", CMR.to_uppercase())).unwrap(),
        leaf
    );
    for bad in [
        "sim{pk(a)}",
        "sim{TRIVIAL}",
        "sim_v0_9_0{TRIVIAL}",
        "sim{asm(00)}",
        "sim{asm()}",
        "sim{asm(zz)}",
        "sim{asm(00),asm(00)}",
    ] {
        assert!(SimplicityLeaf::from_str(bad).is_err(), "{}", bad);
        assert!(
            Tr::<String>::from_str(&format!("eltr(internal,{})", bad)).is_err(),
            "{}",
            bad
        );
    }
    let tr = Tr::<String>::from_str(&format!("eltr(internal,{})", text)).unwrap();
    let mut keys = Vec::new();
    tr.for_each_key(|k| {
        keys.push(k.clone());
        true
    });
    assert_eq!(keys, ["internal"]);
    assert_eq!(tr.iter_scripts().next().unwrap().1.iter_pk().count(), 0);
}

#[test]
fn commitment_vectors_and_analysis() {
    let key = XOnlyPublicKey::from_str(KEY).unwrap();
    let leaf = SimplicityLeaf::from_cmr(Cmr::from_str(CMR).unwrap());
    let text = format!("eltr({}, {})", KEY, leaf).replace(' ', "");
    let tr = Tr::<XOnlyPublicKey>::from_str(&text).unwrap();
    assert_eq!(tr, Tr::from_str(&tr.to_string()).unwrap());
    let (_, script) = tr.iter_scripts().next().unwrap();
    assert_eq!(script.version().as_u8(), 0xbe);
    assert_eq!(script.encode().as_bytes(), leaf.cmr().as_ref());
    assert_eq!(script.max_satisfaction_witness_elements().unwrap(), 3);
    let control = tr
        .spend_info()
        .control_block(&(script.encode(), script.version()))
        .unwrap();
    assert_eq!(control.serialize()[0] & 0xfe, 0xbe);
    assert_eq!(
        tr.address(None, &elements::AddressParams::ELEMENTS)
            .to_string(),
        "ert1psmpfd2fj6zwpw9ugf5f6al8wg7urum6vv3ednhwnskxf6mplz5nst39pkg"
    );
    let expected_control: Vec<u8> = bitcoin::hex::FromHex::from_hex(&format!("be{}", KEY)).unwrap();
    assert_eq!(control.serialize(), expected_control);
    let independent = elements::taproot::TaprootBuilder::new()
        .add_leaf_with_ver(
            0,
            elements::Script::from(leaf.cmr().as_ref().to_vec()),
            elements::taproot::LeafVersion::from_u8(0xbe).unwrap(),
        )
        .unwrap()
        .finalize(&Secp256k1::new(), key)
        .unwrap();
    assert_eq!(tr.spend_info().as_ref(), &independent);
    assert!(tr.max_weight_to_satisfy().is_err());
    assert!(tr.sanity_check().is_err());
    assert!(tr.lift().is_err());
    let mixed =
        Tr::<XOnlyPublicKey>::from_str(&format!("eltr({},{{pk({}),{}}})", KEY, KEY, leaf)).unwrap();
    assert!(mixed.max_weight_to_satisfy().is_err());
    assert!(mixed.lift().is_err());
    assert!(tr.get_satisfaction(()).is_err());
}

#[test]
fn derivation_and_pset_leaf_versions() {
    use elements_miniscript::psbt::{PsbtInputExt, PsbtOutputExt};
    let xpub = "[78412e3a/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*";
    let desc =
        Descriptor::<DescriptorPublicKey>::from_str(&format!("eltr({},sim{{asm({})}})", xpub, CMR))
            .unwrap();
    let secp = Secp256k1::new();
    let d0 = desc.at_derivation_index(0).unwrap();
    let d1 = desc.at_derivation_index(1).unwrap();
    let derived = d0.derived_descriptor(&secp).unwrap();
    assert_ne!(
        derived.script_pubkey(),
        d1.derived_descriptor(&secp).unwrap().script_pubkey()
    );
    let mut input = elements::pset::Input::default();
    let mut output = elements::pset::Output::default();
    input.update_with_descriptor_unchecked(&d0).unwrap();
    output.update_with_descriptor_unchecked(&d0).unwrap();
    let (control, (cmr, ver)) = input.tap_scripts.iter().next().unwrap();
    assert_eq!(ver.as_u8(), 0xbe);
    assert_eq!(cmr.as_bytes(), Cmr::from_str(CMR).unwrap().as_ref());
    assert_eq!(control.leaf_version.as_u8(), 0xbe);
    if let Descriptor::Tr(tr) = d1.derived_descriptor(&secp).unwrap() {
        assert_eq!(tr.iter_scripts().next().unwrap().1.encode(), *cmr);
    } else {
        panic!("taproot expected");
    }
    let output_tree = output.tap_tree.as_ref().unwrap();
    let expected = elements::taproot::TaprootBuilder::new()
        .add_leaf_with_ver(0, cmr.clone(), *ver)
        .unwrap();
    assert_eq!(
        *output_tree,
        elements::pset::TapTree::from_inner(expected).unwrap()
    );
    if let Descriptor::Tr(tr) = &derived {
        assert_eq!(input.tap_merkle_root, tr.spend_info().merkle_root());
    } else {
        panic!("taproot expected");
    }
}

#[test]
fn generic_pset_finalizer_cannot_infer_simplicity_artifact() {
    use elements_miniscript::psbt::{Error, InputError, PsbtExt, PsbtInputExt};
    let desc =
        Descriptor::<DescriptorPublicKey>::from_str(&format!("eltr({},sim{{asm({})}})", KEY, CMR))
            .unwrap()
            .at_derivation_index(0)
            .unwrap();
    let secp = Secp256k1::new();
    let derived = desc.derived_descriptor(&secp).unwrap();
    let tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn::default()],
        output: vec![],
    };
    let mut pset = elements::pset::PartiallySignedTransaction::from_tx(tx);
    pset.inputs_mut()[0].witness_utxo = Some(elements::TxOut {
        script_pubkey: derived.script_pubkey(),
        asset: elements::confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
        value: elements::confidential::Value::Explicit(1000),
        ..elements::TxOut::default()
    });
    pset.inputs_mut()[0]
        .update_with_descriptor_unchecked(&desc)
        .unwrap();
    let before = pset.inputs()[0].final_script_witness.clone();
    assert!(matches!(
        pset.finalize_inp_mut(&secp, 0, elements::BlockHash::from_byte_array([0; 32])),
        Err(Error::InputError(InputError::CouldNotSatisfyTr, 0))
    ));
    assert_eq!(pset.inputs()[0].final_script_witness, before);
}

#[test]
fn reject_nested_leaf_data() {
    for leaf in [
        "sim{pk(a){pk(b),pk(c)}}".to_owned(),
        format!("sim{{asm({}){{x,y}}}}", "00".repeat(32)),
    ] {
        assert!(Tr::<String>::from_str(&format!("eltr(internal,{})", leaf)).is_err());
    }
}

#[test]
fn interpreter_rejects_simplicity_leaf_version() {
    let tr = Tr::<XOnlyPublicKey>::from_str(&format!("eltr({},sim{{asm({})}})", KEY, CMR)).unwrap();
    let (_, leaf) = tr.iter_scripts().next().unwrap();
    let control = tr
        .spend_info()
        .control_block(&(leaf.encode(), leaf.version()))
        .unwrap();
    // Metadata is enough to test refusal. This is not a satisfying witness.
    let witness = vec![
        vec![],
        vec![],
        leaf.encode().into_bytes(),
        control.serialize(),
    ];
    let script_sig = elements::Script::new();
    let script_pubkey = tr.script_pubkey();
    let result = elements_miniscript::interpreter::Interpreter::from_txdata(
        &script_pubkey,
        &script_sig,
        &witness,
        elements::Sequence::ZERO,
        elements::LockTime::ZERO,
    );
    assert!(matches!(
        result,
        Err(elements_miniscript::interpreter::Error::UnsupportedTapLeafVersion(0xbe))
    ));
}
