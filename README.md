# FourQ Setup (Ubuntu)

## 1) Install system prerequisites
```bash
sudo apt update
sudo apt install -y build-essential cmake clang llvm-dev libclang-dev
```

If bindgen cannot find libclang:
```bash
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
```

## 2) Add the crate
```bash
cargo add fourq
```

## 3) Verify integration
```bash
cargo run --release --bin test_fourq
```

Expected output shape:
```text
computed 10 multiplications in <time>
```

## 4) Minimal usage pattern
```rust
use fourq::point::Point;
use fourq::scalar::Scalar;

let s = Scalar::new(rand::random::<[u8; 32]>());
let bytes: [u8; 32] = s.into();
let p = Point::from_hash(&bytes);
let _q = p * s;
```
