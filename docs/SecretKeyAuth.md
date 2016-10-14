# Secret-key authentication

## Example
```C#
var message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
var key = SecretKeyAuth.GenerateKey(); // 32 byte key

// returns a 32 byte authentication code
var signature = SecretKeyAuth.Sign(message, key);

if (SecretKeyAuth.Verify(message, signature, key))
{
    // Message is valid
}
```

## Purpose

This operation computes an authentication tag of a given message using a secret key, and provides a way to verify that the authentication tag is valid. This method is deterministic (the same message and key will always produce the same output).

The computed authentication tag may be public, however your secret key should be kept confidential.

> This operation does not encrypt the message. It only computes and verifies an authentication tag.

## Generate key

__Namespace:__ _Sodium.SecretKeyAuth

```C#
public static byte[] Sodium.SecretKeyAuth.GenerateKey()
```

This method generates a 32 byte key.

## Sign

__Namespace:__ _Sodium.SecretKeyAuth

```C#
pubic static byte[] Sodium.SecretKeyAuth.Sign(byte[] message, byte[] key)
```

This method signs a given `message` using a 32 byte `key`, and will return a 32 byte authentication tag.

_This method internally uses `crypto_auth`._

## Verify

__Namespace:__ _Sodium.SecretKeyAuth

```C#
public static bool Sodium.SecretKeyAuth.Verify(byte[] message, byte[] signature, byte[] key)
```

This method verifies that the given 32 byte `signature` associated with a given `message` and 32 byte `key` is valid. This method will return `true` of the signature is valid, and `false` otherwise.

_This method internally uses `crypto_auth_verify`._
# Algorithm Details

- HMAC-SHA512256