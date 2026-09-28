#![cfg(feature = "simplicity")]
use std::str::FromStr;

use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements_miniscript::descriptor::Tr;
use elements_miniscript::policy::Liftable;
use elements_miniscript::{
    simplicity_lang as simplicity, ForEachKey, SimplicityLeaf,
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
fn reject_nested_leaf_data() {
    for leaf in [
        "sim{pk(a){pk(b),pk(c)}}".to_owned(),
        format!("sim{{asm({}){{x,y}}}}", "00".repeat(32)),
    ] {
        assert!(Tr::<String>::from_str(&format!("eltr(internal,{})", leaf)).is_err());
    }
}
