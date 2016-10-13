# Sealed Public Key Cryptography

## Example
```
var message = System.Text.Encoding.UTF8.GetBytes("My secret message");

// Recipient creates a long-term key pair
var recipientKeyPair = PublicKeyBox.GenerateKeyPair();

// Anonymous sender encrypts a message using an ephemeral key pair
// and the recipient's public key
var encryptedMessage = SealedPublicKeyBox.Create(message, recipientKeyPair.Public);

// Recipient decrypts the ciphertext
var decryptedMessage = SealedPublicKeyBox.Open(encryptedMessage, recipientKeyPair);
```

## Purpose

Sealed boxes are designed so that anonymous individuals can send a message to a given recipient using their public key. Only the recipient can decrypt the message using their private key. Consequently, without additional data the recipient will not be able to identify the sender.

The message is encrypted using an ephemeral key pair whose secret part is destroyed after the message is encrypted.

## Encrypt

__Namespace:__ _Sodium.SealedPublicKeyBox_

```
public static byte[] Sodium.SealedPublicKeyBox.Create(byte[] message, byte[] recipientPublicKey)
public static byte[] Sodium.SealedPublicKeyBox.Create(byte[] message, KeyPair recipientKeyPair)
```

This method encrypts a given message using a 32 byte `recipientPublicKey`. A new key pair is created for each message, and the corresponding public key is attached to the output ciphertext. the secret key is destroyed after the message has been encrypted, and is not available after this method returns.

This method is overloaded to accept either the recipient's public key, or a `KeyPair` instance upon which the `Public` component can be extracted from.

_This method uses internally `crypto_box_seal`._

## Decrypt

__Namespace:__ _Sodium.SealedPublicKeyBox_

```
public static byte[] Sodium.SealedPublicKeyBox.Open(byte[] cipherText, byte[] recipientSecretKey, byte[] recipientPublicKey)
public static byte[] Sodium.SealedPublicKeyBox.Open(byte[] cipherText, KeyPair recipientKeyPair)
```

This method decrypts an encrypted `cipherText` encrypted by `Sodium.SealedPublicKeyBox.Create` using the 32 bytes `recipientSecretKey` and 32 bytes `recipientPublicKey`.

This method is overloaded to accept either the recipient's public and private key, or a `KeyPair` instance upon which the `Public` and `Secret` component can be extracted from.

_This method uses internally `crypto_box_seal_open`._