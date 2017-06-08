# Password Hashing

libsodium-uwp offers two password hashing algorithms: Argon2i, and Scrypt. Access to both hashing algorithms are available through a single method call

## Argon2i

Argon2, the recommended password hashing algorithm by the Password Hashing Competition, is a modern algorithm for securely hashing passwords. Argon2 addresses several key downsides of existing algorithms in that it is designed for the highest memory filling rate, and effective use multiple computing units while still providing defense against tradeoff attacks. Unlike Bcrypt, which just takes a single cost factor, Argon2 is parameterized by three distinct factors:

- A memory cost that defines memory usage of the algorithm
- A time cost that defines the execution time of the algorithm and the number of iterations
- And a parallelism factor, which defines the number of parallel threads

Libsodium's Argon2i implementation exposes the time and cost factor.

## Scrypt

As a conservative alternative to Argon2, Sodium provides an implementation of the Scrypt password hashing function.

## Password Hashing Options

Options can be summarized by the following structure for both Argon2i and Scrypt:

```C#
var options = PasswordHash.CreateOptions(int memory, int time);
```

> Avoid calling `new PasswordHashOptions { }` directly. Use the wrapper function.

The recommended minimum values are outlined below:

__Argon2i__

For Argon2i, the `time_cost` represents the number of iterations, and _must_ be greater than 3. The `memory_cost` factor is represented in `MiB`. The default `memory_cost` is 16384 MiB

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

The algorithm can be selected using the constants provided by `PasswordHash`.

```C#
PasswordHash.Argon2i // Argon2i
PasswordHash.Scrypt // Scrypt
```

## Hashing passwords

__Namespace:__ _Sodium.PasswordHash_

```C#
public static String Sodium.PasswordHash.Hash(String password, int algorithm, PasswordHashOptions options)
```

_Internally this method will use either `crypto_pwhash_scryptsalsa208sha256_str` or `crypto_pwhash_str`, depending upon the algorithm set._

## Verifying passwords

__Namespace:__ _Sodium.PasswordHash_

```C#
public static bool Sodium.PasswordHash.Verify(String hash, String password)
```

_Internally this method will use either `crypto_pwhash_scryptsalsa208sha256_str_verify` or `crypto_pwhash_str_verify`, depending upon the algorithm set._