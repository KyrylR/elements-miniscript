// SPDX-License-Identifier: CC0-1.0
//! Derive an address and PSET metadata for a commitment-only Simplicity leaf.
use std::str::FromStr;

use elements::secp256k1_zkp::Secp256k1;
use elements_miniscript::psbt::{PsbtInputExt, PsbtOutputExt};
use elements_miniscript::{Descriptor, DescriptorPublicKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example CMR. Address derivation does not require the program.
    let cmr = "0526eb603a8936dba018b14794dee96a87a6fd76987dd867c3e5a1773932fdfe";
    let internal_key = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!(
        "eltr({},sim{{asm({})}})",
        internal_key, cmr,
    ))?
    .at_derivation_index(0)?;
    let derived = descriptor.derived_descriptor(&Secp256k1::new())?;
    let address = derived.address(&elements::AddressParams::ELEMENTS)?;
    let mut input = elements::pset::Input::default();
    let mut output = elements::pset::Output::default();
    input.update_with_descriptor_unchecked(&descriptor)?;
    output.update_with_descriptor_unchecked(&descriptor)?;
    let (control, (_, version)) = input.tap_scripts.iter().next().unwrap();
    assert_eq!(version.as_u8(), 0xbe);
    assert!(output.tap_tree.is_some());
    println!("Descriptor: {}", descriptor);
    println!("Address: {}", address);
    println!("Control block bytes: {}", control.serialize().len());
    Ok(())
}
