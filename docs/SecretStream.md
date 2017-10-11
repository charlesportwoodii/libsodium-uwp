# Secret Stream

Stream/file encryption is made available through a high-level API that encrypts a sequence of messages, or a single message split up into an arbitary number of chunks, using a secret key with the following properties:

- Messages cannot be truncated, removed, reordered, duplicated or modified without this being detected by the decryption methods.
- Non-deterministic - the same sequence encrypted twice will produce different ciphertexts.
- An authentication tag is added to each encrypted message, allowing streaming corruption to be detected without having to read the stream until the end.
- Each message can incldue additional data in computation of the message tag.
- Messages can be of arbirary size and length.
- There is no practical limit to the total length of the stream, or the total number of individual messages.
- Ratcheting: at any point in the stream, it's possible to forget the key used to encrypt previous messages and to switch to a new key.
- Nonce and key rotation is automatically handled.

This API can be used to securely send an ordered sequence of messages to a peer. Since the length of the stream is not limited, it can also be used to encrypt files regardless of their size. 
> Please reference the [libsodium documentation](https://download.libsodium.org/doc/secret-key_cryptography/secretstream.html) for more information on secret streams.

## Example

The following is a rough example of how to use the API.

    ```C#
    var key = SecretStream.GenerateKey();
    var header = SecretStream.GenerateHeader();
    var encrypter = new SecretStream(key, header, SecretStream.MODE_PUSH);
    var decrypter = new SecretStream(key, header, SecretStream.MODE_PULL);

    var message1 = "Hello, World!";
    var message2 = "{ \"json\": \"data\" }";
    var message3 = "Some more random messaging";

    var ciphertext1 = encrypter.Push(message1);
    encrypter.Rekey();
    var ciphertext2 = encrypter.Push(message2, SecretStream.TAG_PUSH);
    var ciphertext3 = encrypter.Push(message3, SecretStream.TAG_FINAL);

    int tag = -1;
    var d1 = decrypter.Pull(ciphertext1, out tag);
    // tag == Sodium.SecretStream.TAG_MESSAGE
    decrypter.Rekey();
    var d2 = decrypter.Pull(ciphertext2, out tag);
    // tag == Sodium.SecretStream.TAG_PUSH
    var d3 = decrypter.Pull(ciphertext3, out tag);
    // tag == Sodium.SecretStream.TAG_FINAL
    ```

## Stream Modes

__Namespace:__ _Sodium.SecretStream_

```C#
SecretStream.MODE_PUSH
SecretStream.MODE_PULL
```

The streaming API exposes two distinct modes, one for encrypting, and the other for decrypting a stream.

## Tags

__Namespace:__ _Sodium.SecretStream_

A tag is attached to each message, and may be one of the following:

```C#
SecretStream.TAG_MESSAGE
```
`TAG_MESSAGE` is the default tag that is added. It does not contain any additional information about the nature of the message.

```C#
SecretStream.TAG_PUSH
```
`TAG_PUSH` indicates that the message marks the end of a set of messages, but not the end of a stream. More messages may follow.

```C#
SecretStream.TAG_REKEY
```
`TAG_REKEY` "forgets" the key used to encrypt this message and the previous one, and derives a new secret key.

```C#
SecretStream.TAG_FINAL
```
`TAG_FINAL` indicates that the message marks the end of the stream, and erases the secret key used to encrypt the previous sequence.


## Key Generation

Secret streams require both a key and a header to encrypt and decrypt the header. Both components are needed to encrypt and decrypt a given stream.

__Namespace:__ _Sodium.SecretStream_

```C#
public static byte[] Sodium.PublicKeyBox.GenerateKey()
```

This method returns a 32 byte key. Within the same application you can use this method to generate a 32 byte key for encrypting and decrypting. When working with remote peers however, use a key exchange method such as [`Sodium::ScalarMult::Mult`](ScalarMult.md) to create a 32 byte shared key that can be safely transmitted to the remote peer.

_Internally this method uses `crypto_secretstream_xchacha20poly1305_keygen`._

```C#
public static byte[] Sodium.PublicKeyBox.GenerateHeader()
```

This method returns a 24 byte header.

## Stream Handling

__Namespace:__ _Sodium.SecretStream_

```C#
public SecretStream SecretStream(byte[] key, byte[] header, int mode);
```

A new stream can be created either in encrypt or decrypt mode.

_Internally this method uses `crypto_secretstream_xchacha20poly1305_init_push` or `crypto_secretstream_xchacha20poly1305_init_pull`, depending upon the mode selected._
## Encrypting a Stream

__Namespace:__ _Sodium.SecretStream_

```C#
public byte[] Push(String message);
public byte[] Push(byte[] message);
```

Several methods are exposed to encrypt a new message in the stream. By default, `TAG_MESSAGE` will be used for the tag.

```C#
public byte[] Push(String message, int tag);
public byte[] Push(byte[] message, int tag);
```

One of the aforementioned tags may be defined. This is useful for rekeying the stream or indicating that the stream is final.

```C#
public byte[] Push(String message, int tag, String additionalData);
public byte[] Push(byte[] message, int tag, byte[] additionalData);
```

Additional data may also be included with the stream either as a String or as a byte array.

_Internally this method uses `crypto_secretstream_xchacha20poly1305_push`._

## Decrypting a Stream

__Namespace:__ _Sodium.SecretStream_

```C#
public byte[] Pull(byte[] ciphertext, out int tag);
```

The default method will return a `byte[]` containing the decrypted response, and will `out` the tag used during the encryption process. After decryption, check if `tag == Sodium.SecretStream.TAG_FINAL` to determine if there are more messages to parse.

```C#
public byte[] Pull(byte[] ciphertext, out int tag, byte[] additionalData);
public byte[] Pull(byte[] ciphertext, out int tag, String additionalData);
```

Additional data may also be specified

_Internally this method uses `crypto_secretstream_xchacha20poly1305_pull`._

## Rekeying

__Namespace:__ _Sodium.SecretStream_

```C#
public void Rekey();
```

Rekeying happens automatically, and transparently. If you want to manually rekey, you can either use the `TAG_REKEY` tag with your message, or explicitly call `Rekey()`.

> Note that rekeying must occur at the same point on both the sender and reciever.

_Internally this method uses `crypto_secretstream_xchacha20poly1305_rekey`._