# Utilities

Useful utilities exposed by libsodium.

## Incrementing large numbers

__Namespace:__ _Sodium.Utilities_

```C#
public static byte[] Sodium.Utilities.Increment(byte[] value)
```

A constant-time function to increment a given array of bytes (nonce or a large number). This function considers the number to encoded in little-endian format.

_This function implements `sodium_increment`_

## Constant time comparison of large numbers

__Namespace:__ _Sodium.Utilities_

```C#
public static bool Sodium.Utilities.Compare(byte[] a, byte[] b)
```

This function compares two values in constant-time, and will return `true` if they are the same, and `false` otherwise.

_This function implements `sodium_compare`_

# Other Useful Utilities

While not implemented by this library, you may find the following UWP methods useful when working with this library.

## Converting a string to byte[]

```C#
String str = "My Data";
byte[] message = System.Text.Encoding.UTF8.GetBytes(str);
```

## Convert byte[] to hex

```C#
var data = Sodium.Core.GetRandomBytes(32);
string hex = BitConverter.ToString(data).Replace("-", string.Empty).ToLower();
```

## Convert byte[] to base64

```C#
var data = Sodium.Core.GetRandomBytes(32);
var data = Convert.ToBase64String(bytes);
```

## Convert base64 to byte[]

```C#
byte[] data = Convert.FromBase64String("<base64_encoded_string>==");
```