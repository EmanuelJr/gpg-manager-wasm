# GPG Manager WASM
GPG Manager WASM is a library made in Rust to be compiled in WASM to manage GPG keys.

## Dependencies
- [Rust](https://rustup.rs/)
- [wasm-pack](https://github.com/rustwasm/wasm-pack)

## Using
```js
import * as gpg from 'gpg-manager-wasm'; // Package not published yet

const publicKey = '`-----BEGIN PGP PUBLIC KEY BLOCK-----...';
const privateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----...';
const password = '123456';

// Creating a keyring
const keyring = new gpg.KeyRing();

// Load the public key to keyring
const [fpPublicKey] = keyring.loadKeys(publicKey)
const [fpPrivateKey] = keyring.loadKeys(privateKey);

// Unlock private key to be user
keyring.unlockKey(fpPrivateKey, password);

// Encrypting a payload
const encrypted = keyring.encrypt(fpPrivateKey, 'Hello World!');
// Decrypting a payload
const decrypted = keyring.decrypt(fpPrivateKey, encrypted);

// Signing a payload
const signature = keyring.sign(fpPrivateKey, 'Hello World!');
// Validating a signature, throws if the signature is not valid
keyring.verifySignature(fpPublicKey, signature, 'Hello World!');

// Generating a keypair
const keypair = gpg.generateKey(2048, null, 'John Doe', 'john@doe.com', password);
```

## Building
```sh
wasm-pack build
```
That's it!