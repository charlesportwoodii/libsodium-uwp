# Provided Classes

| Class | Description  |
|-------|--------------|
| [Core](Core.md) | Core cryptographic functions |
| [CryptoHash](CryptoHash.md) | Hashing functions |
| [HMAC-SHA2](HMAC-SHA2.md) | HMAC-SHA2 message authentication |
| [GenericHash](GenericHash.md) | Generic hash |
| [KDF](KDF.md) | Useful Key Derivation Functions (KDF) implementations (non-libsodium) |
| [KeyPair](KeyPair.md) | Curve25519/Ed25519 helpers for managing key pairs |
| [OneTimeAuth](OneTimeAuth.md) | One Time Authentication |
| [PasswordHash](PasswordHash.md) | Hash password |
| [PublicKeyAuth](PublicKeyAuth.md) | Authenticated encryption with a public key |
| [PublicKeyBox](PublicKeyAuth.md) | Encryption with a public key |
| [ScalarMult](ScalarMult.md) | Scalar Multiplication |
| [SealedPublicKeyBox](SealedPublicKeyBox.md) | Anonymous public key encryption |
| [SecretAead](SecretAead.md) | Secret authenticated encryption with additional data |
| [SecretBox](SecretBox.md) | Secret key cryptography |
| [SecretKeyAuth](SecretKeyAuth.md) | Authenticated secret key cryptography |
| [SecretStream](SecretStream.md) | Encrypt and decrypt streams of arbitrary length |
| [ShortHash](ShortHash.md) | SigHash-2-4 Short Hashing |
| [StreamEncryption](StreamEncryption.md) | Streaming encryption with Salsa20, ChaCha20, and XSalsa20 |
| [Utilities](Utilities.md) | libsodium utilities |

# Design Goals

The initial goal of this runtime component was to implement libsodium for UWP using an API similar to that provided by [libsodium-net](https://github.com/adamcaudill/libsodium-net). When a direct 1-1 matching is not possible, the API will implement designs consistent with UWP functions (e.g. `GenericHash` mimics `HashAlgorithmProvider` behavior).

# Using this library

After installation, you can use this library by `using Sodium`. For more indepth examples about using this library, reference the `Tests` directory.

> __NOTE:__ This library is compatible with `libsodium` 1.0.11+. Compatability with version <= 1.0.11 is not guaranteed.
