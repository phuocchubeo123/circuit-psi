# SH-DOPRF

This is a Rust implementation for the paper _Maliciously Secure Shuffled Distributed OPRF with Applications to Private Set Operations_.
At the moment, only the Dodis-Yampolskiy-based SH-DOPRF has been implemented, while the Dark-Matter-based protocol hasn't been implemented.

## Setting up

### Rust 
This library has been tested with rustc 1.95.0.

### FourQ related setup
This library uses FourQ, which is a Rust binding of the FourQ curve's implementation in C++, and clang is required to compile successfully. 
Run the following commands to install the necessary dependencies for FourQ. This code has been tested on Ubuntu 24.01, AWS EC2 c5a.8xlarge instance.
```bash
sudo apt update
sudo apt install -y build-essential cmake clang llvm-dev libclang-dev
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
```

### Build
After installing all prerequisites, the user should be able to build:
```bash
cargo build --release
```

## Running Private Set Operations
We currently support 5 different Private Set Operations protocols, along with their corresponding bin files:
- mq_RPMT: test_mq_rpmt
- PSI-Cardinality: test_psi_cardinality
- PSI-Sum: test_psi_sum
- One-side PSU: test_one_side_psu
- Two-side PSU: test_two_side_psu

Every file has the same syntax to run. In this tutorial we consider running on two terminals on the same local machine. There are two steps to follow:
1. You need to prepare triples to run the protocol. To prepare triples, run the following commands on two different terminals:
```bash
cargo run --release --bin create_fake_triple_interactive -- --side sender --n [n] --addr [address] --port [port] --triples-csv [dest_for_triples] --delta-txt [dest_for_delta]
```
and
```bash
cargo run --release --bin create_fake_triple_interactive -- --side receiver --n [n] --addr [address] --port [port] --triples-csv [dest_for_triples] --delta-txt [dest_for_delta]
```
Running these commands would help you creating fake authenticated multiplication triples, that are sufficient to validate the correctness and the efficiency of the online phase. Explanation for parameters:
- --side: Either sender or receiver.
- --n: Number of triples to prepare.
- --addr: IP Address of the Sender (who will be the TcpListener).
- --port: port that the Sender would listen on.
- --triples-csv: Output triples to this file.
- --delta-txt: The process would also sample a VOLE key for each side. You will need to use the same consistent VOLE key in the online phase, for the multiplication to work.

2. After generating the triples, you can run your favourite PSO protocol. Again, run on two different terminals:
```bash
cargo run --release --bin [bin_file] -- --side sender --addr [address] --port [port] --set-size [size_of_sets] --intersection-size [size_of_intersection] --triple-csv [triples_csv_file] --delta-txt [delta_txt_file]
```
and
```bash
cargo run --release --bin [bin_file] -- --side receiver --addr [address] --port [port] --set-size [size_of_sets] --intersection-size [size_of_intersection] --triple-csv [triples_csv_file] --delta-txt [delta_txt_file]
```
Explanation for parameters:
- --side: Either sender or receiver.
- --addr: IP Address of the Sender (who will be the TcpListener).
- --port: port that the Sender would listen on.
- --set-size: The size of both sets, we exclusively test for balanced setting, so recommend using the same size for both parties.
- --intersection-size: Again, should be set to be the same for both parties.
- --triples-csv: The triples file that you just generated.
- --delta-txt: The VOLE key file that you just generated. 

## Example for running PSI-Sum on 1000 elements:
On one terminal, create the data/ folder and run:
```bash
cargo run --release --bin create_fake_triple_interactive -- --side sender --n 1000 --addr 127.0.0.1 --port 8080 --triples-csv data/triples_sender.csv --delta-txt data/delta_sender.txt
cargo run --release --bin test_psi_sum -- --side sender --addr 127.0.0.1 --port 8080 --set-size 100 --intersection-size 30 --triple-csv data/triples_sender.csv --delta-txt data/delta_sender.txt
```
On the other terminal, run:
```bash
cargo run --release --bin create_fake_triple_interactive -- --side receiver --n 1000 --addr 127.0.0.1 --port 8080 --triples-csv data/triples_receiver.csv --delta-txt data/delta_receiver.txt
cargo run --release --bin test_psi_sum -- --side receiver --addr 127.0.0.1 --port 8080 --set-size 100 --intersection-size 30 --triple-csv data/triples_receiver.csv --delta-txt data/delta_receiver.txt
```
