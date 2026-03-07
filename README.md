# Merkle Tree Library

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Bitcoin](https://img.shields.io/badge/Bitcoin-000?style=for-the-badge&logo=bitcoin&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
![NodeJS](https://img.shields.io/badge/Node%20js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![NPM](https://img.shields.io/badge/npm-CB3837?style=for-the-badge&logo=npm&logoColor=white)

![SHA-256](https://img.shields.io/badge/SHA--256-cryptographic-blue)

**Package**: `@btc-vision/rust-merkle-tree`

## Overview

This project aims to develop a high-performance, secure Merkle tree library in Rust, with seamless integration for both
Rust and Node.js applications. The library leverages SHA-256 as its cryptographic hash function and is designed to be
secure against known vulnerabilities, ensuring robust state proof validations. Optimized for both performance and
security, this library is intended for use in applications that require strong data integrity and validation mechanisms.

## Security Audit

<p align="center">
  <a href="https://verichains.io/">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./AUDIT/verichains-logo.svg">
      <source media="(prefers-color-scheme: light)" srcset="./AUDIT/verichains-logo-dark.svg">
      <img alt="Verichains" src="./AUDIT/verichains-logo.svg" height="32">
    </picture>
  </a>
</p>

This library has been professionally audited by **[Verichains](https://verichains.io/)**, a leading blockchain security
firm. The audit confirms that the codebase is secure and ready for production use.

For audit reports and details, see the [AUDIT](./AUDIT) directory.

## Key Features

- **SHA-256 Hashing**: Utilizes the SHA-256 hashing algorithm to ensure cryptographic security.
- **Cross-Platform**: Designed for both Rust and Node.js environments, providing bindings for easy integration.
- **Secure Against Exploits**: Implements protections against known vulnerabilities like hash collisions and tree
  manipulation.
- **Optimized Performance**: Significantly improved speed and efficiency compared to existing Merkle tree
  implementations like `merkle-tree-sha256`.
- **Comprehensive Testing**: Includes a suite of tests to ensure the library performs securely and accurately.

## Getting Started

### Prerequisites

- **Node.js**: Version 24/25+ or higher is required.
- **Rust**: You must have Rust installed to compile and develop this project.

### Installation

1. **Clone the repository**:

   ```bash
   git clone git://github.com/btc-vision/rust-merkle-tree.git
   cd rust-merkle-tree
   ```

2. **Install dependencies**:

   ```bash
   npm install
   ```

3. **Build the project**:

   For production build:

   ```bash
   npm run build
   ```

   For debug build:

   ```bash
   npm run build:debug
   ```

4. **Run tests**:

   ```bash
   npm test
   ```

## Usage

### Node.js Usage

For Node.js integration, the library provides bindings via N-API.

1. Install the package:

   ```bash
   npm install @btc-vision/rust-merkle-tree
   ```

2. Example of creating a Merkle tree:

   ```typescript
   import { MerkleTree } from '@btc-vision/rust-merkle-tree';

   const leaves: Uint8Array[] = [
       Uint8Array.from([100, 97, 116, 97, 49]),
       Uint8Array.from([100, 97, 116, 97, 50]),
       Uint8Array.from([100, 97, 116, 97, 51]),
   ];
   const tree = new MerkleTree(leaves);
   console.log('Merkle Root:', tree.root());
   ```

### Scripts

- **`npm run build`**: Compiles the Rust code into a release binary.
- **`npm run build:debug`**: Compiles the Rust code with debug information.
- **`npm test`**: Runs the test suite.
- **`npm run coverage`**: Generates Rust code coverage report.

## References

- **Current Rust Merkle Tree Implementation**: [rs-merkle](https://github.com/antouhou/rs-merkle)
- **SHA-256 Merkle Tree for Node.js**: [merkle-tree-sha256](https://github.com/btc-vision/merkle-tree-sha256)
- **N-API for Rust Integration**: [napi.rs](https://napi.rs/)

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvement, feel free to open an issue
or submit a pull request. Signed commits are required, and please adhere to the project's code of conduct.

## License

This project is licensed under the MIT License. For more details, please see the [LICENSE](LICENSE) file.

## Contact

For more information, visit the [OP_NET homepage](https://opnet.org/) or reach out via the repository's GitHub page.
