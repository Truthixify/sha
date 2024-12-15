# SHA Hash Implementations in Rust

This project is a pure Rust implementation of three widely used cryptographic hash algorithms: **SHA-1**, **SHA-256**, and **SHA-512**. These algorithms are implemented from scratch, without relying on external libraries for the core hashing logic.

## Features

- Implements **SHA-1**, **SHA-256**, and **SHA-512** according to their respective specifications:
  - [SHA-1 Specification (FIPS PUB 180-1)](https://csrc.nist.gov/publications/detail/fips/180/1/archive/1995-04-17)
  - [SHA-256 and SHA-512 Specifications (FIPS PUB 180-4)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- Pure Rust implementation with no external dependencies for the core algorithms.
- Fully tested against known test vectors to ensure correctness.

## Getting Started

### Prerequisites

To build and test this project, you need:

- Rust (stable or nightly). Install it via [rustup](https://rustup.rs/).

### Installation

Clone the repository:
```bash
git clone https://github.com/truthixify/sha.git
cd sha
```

### Usage

#### Example: Compute a SHA-256 Hash

```rust
use sha::{Sha, sha256};

fn main() {
    let data = b"hello world";

    // Compute SHA-256 hash
    let hasher = Sha256::new();
    let hash = hasher.digest(data);
    println!("SHA-256: {}", hash);
}
```

#### Supported Hash Functions

- **SHA-1**: `sha1(data: &[u8]) -> String`
- **SHA-256**: `sha256(data: &[u8]) -> [String`
- **SHA-512**: `sha512(data: &[u8]) -> String`

### Testing

The project includes comprehensive test cases using official test vectors from the specifications. To run the tests:

```bash
cargo test
```

## Implementation Details

### SHA-1
- Operates on 512-bit blocks.
- Produces a 160-bit (20-byte) hash output.
- Based on a Merkle-Damgård construction using the Davies-Meyer compression function.

### SHA-256
- Operates on 512-bit blocks.
- Produces a 256-bit (32-byte) hash output.
- Utilizes 64 rounds of processing with a fixed set of constants and bitwise operations.

### SHA-512
- Operates on 1024-bit blocks.
- Produces a 512-bit (64-byte) hash output.
- Similar to SHA-256 but uses a larger word size (64 bits) and 80 rounds.

### Dependencies

- None for hashing logic.
- For hash output, testing and debugging:
  - `hex` (for encoding/decoding hex strings)

## Roadmap

- [x] Implement SHA-1
- [x] Implement SHA-256
- [x] Implement SHA-512
- [ ] Add support for other SHA-2 variants (e.g., SHA-224, SHA-384)

## Contributing

Contributions are welcome! If you'd like to contribute, please:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-xyz`).
3. Commit your changes (`git commit -m 'Add feature xyz'`).
4. Push to your fork (`git push origin feature-xyz`).
5. Open a pull request.

## Acknowledgements

- Inspired by the [SHA specifications](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
- Test vectors from [NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

---
**Happy hashing!**