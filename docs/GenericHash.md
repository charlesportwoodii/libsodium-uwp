# Generic Hashing

GenericHash computes a fixed length fingerprint for an arbitarily long message. This method is useful for computing hashes for:

- File integrity checks
- Creating unique identifies to index arbitarily long data.

## Generate Key

__Namespace:__ _Sodium.GenericHash_

```C#
public static byte[] Sodium.GenericHash.GenerateKey()
```

Generates a 64 byte key

## Hashing

__Namespace:__ _Sodium.GenericHash_

```C#
public static byte[] Sodium.GenericHash.Hash(byte[] message)
public static byte[] Sodium.GenericHash.Hash(String message)
public static byte[] Sodium.GenericHash.Hash(byte[] message, byte[] key)
public static byte[] Sodium.GenericHash.Hash(String message, byte[] key)
public static byte[] Sodium.GenericHash.Hash(byte[] message, byte[] key, int bytes)
public static byte[] Sodium.GenericHash.Hash(String message, byte[] key, int bytes)
```

The `Hash()` generates a fingerprint of a given `message` using an optional key, and produces n `bytes` of output.

The `key` should be between 16, and 64 bytes (or `null`).

The `bytes` should be between 16 and 64 bytes. The minimum recommended length for `bytes`(and the length if not specified) is 32.

_Internally this method uses `crypto_generichash`._

# Algorithm Details
- Blake2