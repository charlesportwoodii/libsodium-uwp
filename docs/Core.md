# Core

Core methods for this library.

## Sodium Version

__Namespace:__ _Sodium.Core_

```C#
public static String SodiumVersionString()
```

This function returns the version number of the `libsodium` library itself. The current version is `1.0.11`.

> Note this will _not_ return the version of `libsodium-uwp`.

## Generating Random Data

__Namespace:__ _Sodium.Core_

```C#
public static byte[] GetRandomBytes(int count)
```

The `GetRandomBytes()` method takes a integer `count`, and produces an unpredictable sequence of bytes. This method is suitable for generating keys, salts, and nonces.

> This method uses an adapted version of `randombytes_sysrandom.c` to generate random bytes. As `RtlGenRandom` is not available for mobile targets, this library uses `Windows.Security.Cryptography.CryptographicBuffer.GenerateRandom()` instead to securely generate random data.

__Note:__ In classes where appropriate, there are `GenerateKey()` and/or `GenerateNonce()` methods that return a byte array of the correct size.

## Generate a Random Number

__Namespace:__ _Sodium.Core_

```C#
public static int GetRandomNumber(int upper_bound)
```

This method returns an unpredictable valued between 0 and `upper_bound`.

> The maximum possible input for `upper_bound` is: `INT_MAX` (2147483647)