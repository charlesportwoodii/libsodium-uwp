# Stream Cipher

libsodium-uwp provides access to all 3 streaming ciphers provided by libsodium

## Key Generating

__Namespace:__ _Sodium.StreamEncryption_

```C#
static byte[] Sodium.StreamEncryption.GenerateKey()
```

This will generate a 32 byte key from `Sodium.Core.GetRandomBytes(32)`

## XSalsa20

XSalsa20 is a stream cipher based on Salsa20, but has a 192 bit nonce instead of a 64 bit nonce.

XSalsa20 uses a 256 bit key, and the first 128 bits of the nonce to compute a subkey, which is then used with the remaining 64 bits of the nonce to generate the stream.

XSalsa20 is immune to timing attacks, and provides its own 64 bit block counter to avoid incrementing the nonce after each block.

### Generate nonce

__Namespace:__ _Sodium.StreamEncryption_

```C#
static byte[] Sodium.StreamEncryption.GenerateNonce()
static byte[] Sodium.StreamEncryption.GenerateNonceXSalsa20()
```

This will generate a 32 byte nonce from `Sodium.Core.GetRandomBytes(32)`.

> For compatability with `libsodium-net`, `GenerateNonce` is exposed in addition to `GenerateNonceXSalsa20`

### Encrypt

__Namespace:__ _Sodium.StreamEncryption_

```C#
public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
public static byte[] Encrypt(String message, byte[] nonce, byte[] key)
public static byte[] EncryptXSalsa20(byte[] message, byte[] nonce, byte[] key)
public static byte[] EncryptXSalsa20(String message, byte[] nonce, byte[] key)
```

Encrypt expects a `message`, a 24 byte `nonce`, and a 32 byte `key`, and will return a ciphertext (which is the message combined with the output of the stream cipher using the XOR operation, and does not include an authentication tag).

> For compatability with `libsodium-net`, `Encrypt` is directly exposed. `EncryptXSalsa20` is a direct reference to this method.

_Internally this method used `crypto_stream_xsalsa20_xor`._

### Decrypt

__Namespace:__ _Sodium.StreamEncryption_

```C#
public static byte[] Decrypt(byte[] cipherText, byte[] nonce, byte[] key)
public static byte[] Decrypt(String cipherText, byte[] nonce, byte[] key)
public static byte[] DecryptXSalsa20(byte[] cipherText, byte[] nonce, byte[] key)
public static byte[] DecryptXSalsa20(String cipherText, byte[] nonce, byte[] key)
```

Decrypt expects a `ciphertext`, a 24 byte `nonce`, and a 32 byte `key`, and will return a decrypted byte array message.

> For compatability with `libsodium-net`, `Decrypt` is directly exposed. `DecryptXSalsa20` is a direct reference to this method.

_Internally this method used `crypto_stream_xsalsa20_xor`._

## ChaCha20

ChaCha20 is a stream cipher variant of Salsa20 developed by Daniel J.Bernstein with better diffusion. ChaCha20 expands a 256 bit key int 2^64 randomly accessible streams, each containing 2^64 randomly accessible 64 byte blocks.

ChaCha20 doesn't require any lookup tables, and avoids the possibility of timing attacks. ChaCha20 works like a block cipher used in counter mode. It has a dedicated 64 bit block counter to avoid incrementing the nonce after each block.

### Generate nonce

__Namespace:__ _Sodium.StreamEncryption_

```C#
static byte[] Sodium.StreamEncryption.GenerateNonceChaCha20()
```

This will generate a 8 byte nonce from `Sodium.Core.GetRandomBytes(8)`.

### Encrypt

__Namespace:__ _Sodium.StreamEncryption_

```C#
public static byte[] EncryptChaCha20(byte[] message, byte[] nonce, byte[] key)
public static byte[] EncryptChaCha20(String message, byte[] nonce, byte[] key)
```

Encrypt expects a `message`, a 8 byte `nonce`, and a 32 byte `key`, and will return a ciphertext (which is the message combined with the output of the stream cipher using the XOR operation, and does not include an authentication tag).

_Internally this method used `crypto_stream_chacha20_xor`._

### Decrypt

__Namespace:__ _Sodium.StreamEncryption_

```C#
public static byte[] DecryptChaCha20(byte[] cipherText, byte[] nonce, byte[] key)
public static byte[] DecryptChaCha20(String cipherText, byte[] nonce, byte[] key)
```

Decrypt expects a `ciphertext`, a 8 byte `nonce`, and a 32 byte `key`, and will return a decrypted byte array message.

_Internally this method used `crypto_stream_chacha20_xor`._

## Salsa20

Salsa20 is a stream cipher developed by Daniel J.Bernstein. Salsa20 expands a 256 bit key int 2^64 randomly accessible streams, each containing 2^64 randomly accessible 64 byte blocks.

Salsa20 doesn't require any lookup tables, and avoids the possibility of timing attacks. Salsa20 works like a block cipher used in counter mode. It has a dedicated 64 bit block counter to avoid incrementing the nonce after each block.

### Generate nonce

__Namespace:__ _Sodium.StreamEncryption_

```C#
static byte[] Sodium.StreamEncryption.GenerateNonceSalsa20()
```

This will generate a 24 byte nonce from `Sodium.Core.GetRandomBytes(24)`.

### Encrypt

__Namespace:__ _Sodium.StreamEncryption_

```C#
public static byte[] EncryptSalsa20(byte[] message, byte[] nonce, byte[] key)
public static byte[] EncryptSalsa20(String message, byte[] nonce, byte[] key)
```

Encrypt expects a `message`, a 24 byte `nonce`, and a 32 byte `key`, and will return a ciphertext (which is the message combined with the output of the stream cipher using the XOR operation, and does not include an authentication tag).

_Internally this method used `crypto_stream_salsa20_xor`._

### Decrypt

__Namespace:__ _Sodium.StreamEncryption_

```C#
public static byte[] DecryptSalsa20(byte[] cipherText, byte[] nonce, byte[] key)
public static byte[] DecryptSalsa20(String cipherText, byte[] nonce, byte[] key)
```

Decrypt expects a `ciphertext`, a 24 byte `nonce`, and a 32 byte `key`, and will return a decrypted byte array message.

_Internally this method used `crypto_stream_salsa20_xor`._