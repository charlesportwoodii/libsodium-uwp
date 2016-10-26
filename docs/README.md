# Provided Classes

| Class | Description  |
|-------|--------------|
| [Core](Core.md) | Core cryptographic functions |
| [CryptoHash](CryptoHash.md) | Hashing functions |
| [HMAC-SHA2](HMAC-SHA2.md) | HMAC-SHA2 keyhed message authentication |
| [KDF](KDF.md) | Useful Key Derivation Functions (KDF) implementations (non-libsodium) |
| [KeyPair](KeyPair.md) | Curve25519/Ed25519 helpers for managing key pairs |
| [OneTimeAuth](OneTimeAuth.md) | One Time Authentication |
| [PublicKeyAuth](PublicKeyAuth.md) | Authenticated encryption with a public key |
| [PublicKeyBox](PublicKeyAuth.md) | Encryption with a public key |
| [SealedPublicKeyBox](SealedPublicKeyBox.md) | Anonymous public key encryption |
| [ScalarMult](ScalarMult.md) | Scalar Multiplication |
| [SecretAead](SecretAead.md) | Secret authenticated encryption with additional data |
| [SecretBox](SecretBox.md) | Secret key cryptography |
| [SecretKeyAuth](SecretKeyAuth.md) | Authenticated secret key cryptography |
| [StreamEncryption](StreamEncryption.md) | Streaming encryption with Salsa20, ChaCha20, and XSalsa20 |
| [Utilities](Utilities.md) | libsodium utilities |

# Design Goals

The primary goal of this runtime component is to implement libsodium for UWP using an API similar to that provided by [libsodium-net](https://github.com/adamcaudill/libsodium-net).

# Using this library

After installation, you can use this library by `using Sodium`. For more indepth examples about using this library, reference the `Tests` directory.

> __NOTE:__ This library is compatible with `libsodium` 1.0.11+. Compatability with version <= 1.0.11 is not guaranteed.