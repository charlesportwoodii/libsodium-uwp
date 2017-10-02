# Password Hashing

libsodium-uwp offers three password hashing algorithms: Argon2i, Argon2id, and Scrypt. Access to all hashing algorithms are available through a single method call

## Argon2i & Argon2id

Argon2, the recommended password hashing algorithm by the Password Hashing Competition, is a modern algorithm for securely hashing passwords. Argon2 addresses several key downsides of existing algorithms in that it is designed for the highest memory filling rate, and effective use multiple computing units while still providing defense against tradeoff attacks. Unlike Bcrypt, which just takes a single cost factor, Argon2 is parameterized by three distinct factors:

- A memory cost that defines memory usage of the algorithm
- A time cost that defines the execution time of the algorithm and the number of iterations
- And a parallelism factor, which defines the number of parallel threads

Libsodium's Argon2i & Argon2id implementation exposes the time and cost factor.

## Scrypt

As a conservative alternative to Argon2, Sodium provides an implementation of the Scrypt password hashing function.

## Password Hashing Options

Options can be summarized by the following structure for Argon2i, Argon2id, and Scrypt

```C#
var options = PasswordHash.CreateOptions(int memory, int time);
```

> Avoid calling `new PasswordHashOptions { }` directly. Use the wrapper function.

The recommended minimum values are outlined below:

__Argon2i & Argon2id__

For Argon2i and Argon2id, the `time_cost` represents the number of iterations, and _must_ be greater than 3. The `memory_cost` factor is represented in `MiB`. The default `memory_cost` is 16384 MiB

```C#
time_cost = 3,
memory_cost = 1<<14
```

__Scrypt__

For Scrypt, the `time_cost` represents the number of iterations, and the `memory_cost` factor is represented in `MiB`. 

```C#
time_cost = 512,
memory_cost = 1<<14
```

## Algorithm Selection

The algorithm can be selected using the constants provided by `PasswordHash`. By default passwords will be hashed using `Password.Argon2id`.

```C#
PasswordHash.Argon2i // Argon2i
PasswordHash.Argon2id // Argon2id
PasswordHash.Scrypt // Scrypt
```

## Hashing passwords

__Namespace:__ _Sodium.PasswordHash_

```C#
public static String Sodium.PasswordHash.Hash(String password, PasswordHashOptions options, int algorithm = Password.Argon2id)
```

_Internally this method will use either `crypto_pwhash_scryptsalsa208sha256_str` or `crypto_pwhash_str_alg`, depending upon the algorithm set._

## Verifying passwords

__Namespace:__ _Sodium.PasswordHash_

```C#
public static bool Sodium.PasswordHash.Verify(String hash, String password)
```

_Internally this method will use either `crypto_pwhash_scryptsalsa208sha256_str_verify` or `crypto_pwhash_str_verify`, depending upon the algorithm set._

## Determine if password needs to be rehashed

__Namespace:__ _Sodium.PasswordHash_

```C#
public static bool Sodium.PasswordHash.NeedsRehash(String hash, PasswordHashOptions options);
```

_Internally this method uses `crypto_pwhash_str_needs_rehash`. Note that this method only works with `Password.Argon2i` and `Password.Argon2id`._