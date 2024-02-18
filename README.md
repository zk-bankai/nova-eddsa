# nova-eddsa

_High Throughput Ed25519 Signature Verification using Nova_ 

This repository contains Ed25519 signature verification circuit which is represented as a step function in Nova computation. At each step, the step function takes hash of the message, public key and the signature as input followed by verifying the signature in circuit. The verification circuit is dependent on non-native field arithmetic which is implemented at [bellpepper-ed25519](https://github.com/lurk-lab/bellpepper-gadgets/tree/main/crates/ed25519).  

## Build

Clone the repository and run the following commands:
```bash
cd nova-eddsa/
cargo build --release --examples
```

## Tests

To run the tests:
```bash
cargo test --release
```

To run a specific test, specify it's name as follows:
```bash
cargo test --release [name_of_test]
```

## Running the example

To run an example for signature verification, run the following commands by passing the number of signatures as argument:
```bash
cargo run --release --example verify [num_of_signatures]
```

## Generating the benchmarks

To generate benchmarks run  the following commands:

```bash
cargo build --release --examples
./genlog_all.sh
```

To generate benchmarks for specific number of signatures run:
```bash
cargo build --release --examples
./genlog.sh [num_of_signatures]
```

The benchmarks will be generated in the [`logs`](/logs/) directory. It contains the files `output_N.txt` where `N` is the number of signatures.

### Existing Benchmarks
The existing files in the logs directory were generated on a **2.30GHz Intel Xeon Gold 6314U CPU with 64 cores and 125GB RAM**.
- For all iterations
  - Verification time was under 1 sec.
  - Proof size was about 11.4KB.
- The proving time for 32 signatures was under 69 sec. Proving times for other lengths are shown below.

### Proving times
```bash
$ grep "Total proving time is" $(ls -rt logs/output_*)
logs/output_8.txt:Total proving time is 36.821469524s
logs/output_16.txt:Total proving time is 47.60963894s
logs/output_32.txt:Total proving time is 68.826601078s
logs/output_64.txt:Total proving time is 111.198203602s
logs/output_128.txt:Total proving time is 196.445131859s
```

### Verification times
```bash
$ grep "CompressedSNARK::verify" $(ls -rt logs/output_*)
logs/output_8.txt:CompressedSNARK::verify: true, took 943.797593ms
logs/output_16.txt:CompressedSNARK::verify: true, took 935.054545ms
logs/output_32.txt:CompressedSNARK::verify: true, took 916.476058ms
logs/output_64.txt:CompressedSNARK::verify: true, took 916.408182ms
logs/output_128.txt:CompressedSNARK::verify: true, took 937.352972ms
```

### Proof sizes
```bash
$ grep "len" $(ls -rt logs/output_*)
logs/output_8.txt:CompressedSNARK::len 11405 bytes
logs/output_16.txt:CompressedSNARK::len 11412 bytes
logs/output_32.txt:CompressedSNARK::len 11402 bytes
logs/output_64.txt:CompressedSNARK::len 11404 bytes
logs/output_128.txt:CompressedSNARK::len 11407 bytes
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
