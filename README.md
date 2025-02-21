# Shardus Crypto Utils

Shardus Crypto Utils is a tool providing a set of cryptographic utility functions specifically designed for developers working with the Shardus core. It offers a simplified interface to node-sodium cryptographic functions, which are fundamental to the Shardus project.

## Installation

You can install Shardus Crypto Utils via npm:

```bash
npm install @shardeum-foundation/lib-crypto-utils
```

## Usage

```JavaScript
const crypto = require('@shardeum-foundation/lib-crypto-utils')

// Module has a constructor that takes in a 32-byte hex key as required by node-sodium for generic hashing
crypto.init('64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347')

// Uses json-stable-stringify to stringify an object in a consistent sorted manner; returns a string
crypto.stringify(obj)

/*
  Returns a 32-byte random hex string by default, otherwise you can
  specify how many bytes you would like to generate
*/
crypto.randomBytes([bytes])

// Returns the hash of the input, output format can be specified as 'hex' or 'buffer'
crypto.hash(input [, fmt])

/*
  Returns the hash of the provided object as a hex string, optional
  parameter to hash the object without the "sign" field (default is
  false, can be passed true to hash without "sign")
*/
crypto.hashObj(obj [, removeSign])

// Generates and returns {publicKey, secretKey} as hex strings
crypto.generateKeypair()

// Returns a signature obtained by signing the input with the sk
crypto.sign(input, sk)

/*
  Attaches a sign field to the input object, containing a signed version
  of the hash of the object, along with the public key of the signer
*/
crypto.signObj(obj, sk, pk)

// Returns true if the input was signed by the owner of the pk
crypto.verify(input, sig, pk)

/*
  Returns true if the hash of the object minus the sign field matches
  the signed message in the sign field
*/
crypto.verifyObj(obj)
```

Here's how you can use Shardus Crypto Utils in your Node.js application:

```JavaScript
const crypto = require('shardus-crypto-utils')
crypto.init('64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347')

let msg = crypto.hash('Hello world!')
console.log(msg)
```

## Release

To release a new version of Shardus Crypto Utils, run the following command:

```sh
npm run release
```

This will handle version bumping, generating release notes, tagging, and publishing to npm.

## Contributing

Contributions are very welcome! Everyone interacting in our codebases, issue trackers, and any other form of communication, including chat rooms and mailing lists, is expected to follow our [code of conduct](./CODE_OF_CONDUCT.md) so we can all enjoy the effort we put into this project.
