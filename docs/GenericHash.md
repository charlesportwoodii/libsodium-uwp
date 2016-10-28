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

## Multi-Part Hashing (Stream)

Large files or streams can also be hashed using `GenericHash`, `GenericHashAlgorithmProvider`, and `GenericHashAlgorithmNames`. The API for `GenericHash` is identical to the API provided by `MacAlgorithmProvider` and `HashAlgorithmProvider`. The `key` and `byte` requirements are identical to those outlined by `GenericHash.Hash`.

### Large block example

```C#
GenericHashAlgorithmProvider provider = GenericHashAlgorithmProvider.OpenAlgorithm(GenericHashAlgorithmNames.Blake2);
var key = GenericHash.GenerateKey();

GenericHash hash = provider.CreateHash();
// GenericHash hash = provider.CreateHash(key);
// GenericHash hash = provider.CreateHash(key, 64);

IBuffer data = CryptographicBuffer.ConvertStringToBinary("A really really long text string...", BinaryStringEncoding.Utf8);
hash.Append(data);

byte[] final = hash.GetValueAndReset();
```

### Streaming example

```C#
GenericHashAlgorithmProvider provider = GenericHashAlgorithmProvider.OpenAlgorithm(GenericHashAlgorithmNames.Blake2);
var stream = await file.OpenStreamForReadAsync();
var inputStream = stream.AsInputStream();
uint capacity = 100000000;
Windows.Storage.Streams.Buffer buffer = new Windows.Storage.Streams.Buffer(capacity);
GenericHash hash = provider.CreateHash();

while (buffer.Length > 0)
{
    await inputStream.ReadAsync(buffer, capacity, InputStreamOptions.None);
    hash.Append(buffer);
}

string hashText = CryptographicBuffer.EncodeToHexString(hash.GetValueAndReset()).ToUpper();
```

_Internally this method uses `crypto_generichash_init`, `crypto_generichash_update`, and `crypto_generichash_final`._

# Algorithm Details
- Blake2