![Build](https://github.com/ElementsProject/elements-miniscript/workflows/Continuous%20integration/badge.svg)

**Minimum Supported Rust Version:** 1.74.0

*This crate uses "2018" edition

# Elements Miniscript
This library is a fork of [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) for elements.


## High-Level Features

This library supports

* [Output descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
including embedded Miniscripts
* Parsing and serializing descriptors to a human-readable string format
* Compilation of abstract spending policies to Miniscript (enabled by the
`compiler` flag)
* Semantic analysis of Miniscripts and spending policies, with user-defined
public key types
* Encoding and decoding Miniscript as Bitcoin Script, given key types that
are convertible to `bitcoin::PublicKey`
* Determining satisfiability, and optimal witnesses, for a given descriptor;
completing an unsigned `elements::TxIn` with appropriate data
* Determining the specific keys, hash preimages and timelocks used to spend
coins in a given Bitcoin transaction

More information can be found in [the documentation](https://docs.rs/elements-miniscript)
or in [the `examples/` directory](https://github.com/ElementsProject/elements-miniscript/tree/master/examples)

## Simplicity descriptors

Enable the `simplicity` feature to use `eltr(KEY,sim{asm(CMR)})`, including
mixed Miniscript/Simplicity trees. CMR is a 32-byte commitment Merkle root written
as 64 hexadecimal characters. The descriptor stores the commitment. Retain the
matching program separately because it is needed to spend the output. Parsing
accepts uppercase hex and display normalizes it to lowercase, which can change
the descriptor checksum.

Use a CMR descriptor to derive addresses and control blocks.
`PsbtExt::update_input_with_descriptor`, `update_output_with_descriptor` and the
`update_with_descriptor_unchecked` methods on PSET inputs and outputs populate
metadata with Simplicity's `0xbe` leaf version. `SimplicityLeaf::from_cmr`
constructs a leaf from a CMR. The crate re-exports `simplicity-lang`, including its `Cmr` type, as
`elements_miniscript::simplicity_lang`. Accepting a CMR does not validate its
program or establish that it can be spent.

A CMR does not reveal the program's keys. Key iteration skips CMR leaves, and
key derivation leaves their commitments unchanged. A successful `for_each_key`
predicate therefore says nothing about keys used by the committed program.
Likewise, `for_any_key` returning false does not rule out a matching key in that
program. The descriptor's internal key and Miniscript leaves still support
derivation.

Policy forms such as `sim{pk(KEY)}` are rejected. For an existing output, use the
CMR recorded when it was created or computed from its original program.

Run the offline address and metadata example:

```sh
cargo run --features simplicity --example simplicity_descriptors
```

The crate does not construct Simplicity witnesses. Generic satisfaction skips
Simplicity leaves in mixed trees, and PSET signing and finalization do not support
Simplicity script paths. The Miniscript interpreter and `PsbtExt::extract` reject
Simplicity script-path witnesses. `Tr::sanity_check`, `Tr::max_weight_to_satisfy`
and `Tr::max_satisfaction_weight` return errors for trees containing Simplicity.
`TapLeafScript::max_satisfaction_size` cannot bound witness bytes from a CMR and
also returns an error. Semantic lifting fails because the CMR does not expose
the spending conditions.

## Building

The cargo feature `std` is enabled by default. At least one of the features `std` or `no-std` or both must be enabled.

Enabling the `no-std` feature does not disable `std`. To disable the `std` feature you must disable default features. The `no-std` feature only enables additional features required for this crate to be usable without `std`. Both can be enabled without conflict.

## Benchmarking

To run the benchmarks run `RUSTFLAGS=--cfg=miniscript_bench cargo +nightly bench --all-features`.

## Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features on **Rust 1.74.0**.


Some dependencies do not play nicely with our MSRV, if you are running the tests
you may need to pin as follows:

```
cargo update -p byteorder --precise 1.4.3
```

Note this list could sometimes be not exhaustive because not enforced by CI. 
If you have any issues check the script executed in CI: `contrib/test.sh`

## Contributing
Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[##miniscript](https://web.libera.chat/?channels=##miniscript) on Libera.


## Release Notes

See [CHANGELOG.md](CHANGELOG.md).


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE). We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX
IDs](https://spdx.dev/ids/).
