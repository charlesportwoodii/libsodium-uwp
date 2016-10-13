# Provided Classes

| Class | Description  |
|-------|--------------|
| [Core](Core.md) | Core cryptographic functions |
| [CryptoHash](CryptoHash.md) | Hashing functions|
| [KeyPair](KeyPair) | Curve25519/Ed25519 helpers for managing key pairs|
| [PublicKeyAuth](PublicKeyAuth.md) | Authenticated encryption with a public key|
| [PublicKeyBox](PublicKeyAuth.md) | Encryption with a public key |
| [SealedPublicKeyBox](SealedPublicKeyBox.md) | Anonymous public key encryption |
| [SecretAead](SecretAead.md) | Secret authenticated encryption with additional data |
| [SecretBox](SecretBox.md) | Secret key cryptography |
| [SecretKeyAuth](SecretKeyAuth.md) | Authenticated secret key cryptography |
| [Utilities](Utilities.md) | libsodium utilities |

# Design Goals

The primary goal of this runtime component is to implement libsodium for UWP using an API similar to that provided by [libsodium-net](https://github.com/adamcaudill/libsodium-net).

# Using this library

After installation, you can use this library by `using Sodium`.