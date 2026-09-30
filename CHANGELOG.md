# Unreleased

- Replace Simplicity policy descriptors with commitment-only `sim{asm(CMR)}` leaves. `TapTree::SimplicityLeaf` and `TapLeafScript::Simplicity` now hold `SimplicityLeaf` values instead of policies. The `sim{POLICY}` syntax is no longer accepted.
- Re-export the `simplicity-lang` crate as `simplicity_lang` for constructing CMR leaves without a separate dependency.
- Leave CMR leaves unchanged during key derivation and omit them from key iteration. The committed program's keys cannot be recovered from its CMR.
- Fix PSET output trees to retain Simplicity's `0xbe` leaf version instead of using the default Tapscript version.
- Make `Tr::sanity_check` return `AnalysisError::SimplicityUnsupported` when it encounters a Simplicity leaf, instead of skipping that leaf.
- Make `Tr::max_weight_to_satisfy` and `Tr::max_satisfaction_weight` reject trees containing Simplicity instead of calculating a bound that omits those leaves. `TapLeafScript::max_satisfaction_size` returns `SimplicityUnsupported` instead of `Malleable`.
- Return `LiftError::SimplicityLift` instead of panicking when lifting Simplicity leaves.
- Correct `TapLeafScript::max_satisfaction_witness_elements` from 2 to 3 for Simplicity, excluding the control block.
- Make `Interpreter::from_txdata` reject nondefault Taproot leaf versions with `interpreter::Error::UnsupportedTapLeafVersion` before decoding their bytes as Miniscript.
- Add an offline example for address derivation and PSET metadata with a CMR leaf.

The new variants in `AnalysisError`, `LiftError` and `interpreter::Error` require
updates to exhaustive matches on those enums.

The removed `sim{POLICY}` parser mishandled `and`/`or` operands and nested leaf
data, so its commitments could represent different spending conditions from the
descriptor text. Describe existing outputs with `sim{asm(CMR)}` using their
original program commitment. Compiling the written policy can produce a
different CMR.

# 0.5.0 - Sep 20, 2026

- Update rust-elements to 0.27.0 and simplicity-lang to 0.9.0.
- Raise MSRV to Rust 1.74.0.
- Adapt hash, hex, witness, asset and PSET handling to the updated Elements APIs.
- Report Simplicity leaves as unsatisfiable until their descriptor integration is rewritten.

# 0.4.0 - Oct 8, 2024

- Use rust-bitcoin 0.32.0 and rust-elements 0.25.0 [#90](https://github.com/ElementsProject/elements-miniscript/pull/90)
- Check input charset [#92](https://github.com/ElementsProject/elements-miniscript/pull/92)
- Fix a bunch of clippy lints and get CI working again [#89](https://github.com/ElementsProject/elements-miniscript/pull/89)
- avoid setting {BITCOIND,ELEMENTSD}\_EXE in setup [#88](https://github.com/ElementsProject/elements-miniscript/pull/88)
- [Removed `to_string_no_chksum`](https://github.com/ElementsProject/elements-miniscript/pull/86). This method was poorly-named and broken. Use the alternate display `{:#}` formatter instead to format descriptors without a checksum.
- Implement federation descriptor tweak with claiming script to match elements core getpeginaddress [#87](https://github.com/ElementsProject/elements-miniscript/pull/87)
- elip151: multisig test vectors [#84](https://github.com/ElementsProject/elements-miniscript/pull/84)

# 0.3.1 - May 10, 2024

- [Fixed](https://github.com/ElementsProject/elements-miniscript/pull/81) ELIP-151 hash calculation

# 0.3.0 - Jan 30, 2024

- Add simplicity
- Use rust-bitcoin 0.31.0
- [elip150](https://github.com/ElementsProject/ELIPs/blob/main/elip-0150.mediawiki)
- [elip151](https://github.com/ElementsProject/ELIPs/blob/main/elip-0151.mediawiki)

# 0.2.0 - June 15, 2023

- Still rapid iteration, very unstable.
