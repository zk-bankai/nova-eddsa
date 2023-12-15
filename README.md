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
  - Proof size was about 11.5KB.
- The proving time for 200 signatures was under 5 mins. Proving times for other lengths are shown below.

### Proving times
```bash
$ grep "Total proving time is" $(ls -rt logs/output_*)
logs/output_2.txt:Total proving time is 26.084653688s
logs/output_10.txt:Total proving time is 36.495504574s
logs/output_32.txt:Total proving time is 64.720713542s
logs/output_50.txt:Total proving time is 88.819232145s
logs/output_100.txt:Total proving time is 154.870464943s
logs/output_150.txt:Total proving time is 218.779994537s
logs/output_200.txt:Total proving time is 284.162978356s
```

### Verification times
```bash
$ grep "CompressedSNARK::verify" $(ls -rt logs/output_*)
logs/output_2.txt:CompressedSNARK::verify: true, took 931.929104ms
logs/output_10.txt:CompressedSNARK::verify: true, took 926.144623ms
logs/output_32.txt:CompressedSNARK::verify: true, took 926.004416ms
logs/output_50.txt:CompressedSNARK::verify: true, took 928.002862ms
logs/output_100.txt:CompressedSNARK::verify: true, took 927.487829ms
logs/output_150.txt:CompressedSNARK::verify: true, took 922.853824ms
logs/output_200.txt:CompressedSNARK::verify: true, took 923.464456ms
```

### Proof sizes
```bash
$ grep "len" $(ls -rt logs/output_*)
logs/output_2.txt:CompressedSNARK::len 11375 bytes
logs/output_10.txt:CompressedSNARK::len 11406 bytes
logs/output_32.txt:CompressedSNARK::len 11408 bytes
logs/output_50.txt:CompressedSNARK::len 11402 bytes
logs/output_100.txt:CompressedSNARK::len 11407 bytes
logs/output_150.txt:CompressedSNARK::len 11407 bytes
logs/output_200.txt:CompressedSNARK::len 11408 bytes
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
