# CryptoHash

Common hashing functions.

## Hash

__Namespace:__ _Sodium.CryptoHash_

```C#
public static byte[] Sodium.CryptoHash.Hash(byte[] message)
public static byte[] Sodium.CryptoHash.Hash(String message)
```

`Hash` implemented the default hashing algorithm provided by libsodium. Presently this is returns a SHA 512 byte encoding of a given message. The output hash will be a 64 byte array.

_This method implements `crypto_hash`._

## Sha256

__Namespace:__ _Sodium.CryptoHash_

```C#
public static byte[] Sodium.CryptoHash.Sha256(byte[] message)
public static byte[] Sodium.CryptoHash.Sha256(String message)
```

`Sha256` returns a SHA 256 byte encoding of a given message. The output hash will be a 32 byte array.

_This method implements `crypto_hash_sha256`_.

## Sha512

__Namespace:__ _Sodium.CryptoHash_

```C#
public static byte[] Sodium.CryptoHash.Sha512(byte[] message)
public static byte[] Sodium.CryptoHash.Sha512(String message)
```

`Sha512` returns a SHA 512 byte encoding of a given message. The output hash will be a 64 byte array.

_This method implements `crypto_hash_sha512`._