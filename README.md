# Prerequisites

## Rust 
This library has been tested with rustc 1.95.0.

## FourQ related setup
This library uses FourQ, which is a Rust binding of the FourQ curve's implementation in C++, and clang is required to compile successfully:
```bash
sudo apt update
sudo apt install -y build-essential cmake clang llvm-dev libclang-dev
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
```

## Build
After installing all prerequisites, the user should be able to build:
```bash
cargo build --release
```