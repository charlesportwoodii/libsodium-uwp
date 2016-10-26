# Short Input Hashing

`ShortHash.Hash` outputs a short but unpredecitable value for a given key and message. ShortHash is optimized for short inputs.

Use cases include:

- Hash tables
- Probabilistic data structures (such as Bloom filters)
- Integrity checking interactive protocols

> Note: `ShortHash.Hash` will only generate 64 bits of output, and should _not_ be considered collision resistant.

## Example

```C#
var key = ShortHash.GenerateKey();
var message = "A short message to hash";

var hash = ShortHash.Hash(message, key);
```

## Key generation

__Namespace:__ _Sodium.ShortHash_

```C#
public static byte[] Sodium.ShortHash.GenerateKey()
```

Generates a 16 byte key

_Internally this method will used `Sodium.Core.GenerateBytes(32)`_

## Hashing

__Namespace:__ _Sodium.ShortHash_

```C#
public static byte[] Hash(byte[] message, byte[] key)
public static byte[] Hash(string message, byte[] key)
public static byte[] Hash(string message, string key)
```

This method computes an 8 byte fingerprint for the given `message`, using a 16 byte `key`. This method is deterministic, in that the same input with the same key will always produce the same hash.

_Internally this method used `crypto_shorthash`._

## Algorithm Details

- SipHash-2-4