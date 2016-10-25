# Scalar Multiplication

The following internal functions are exposed and documented for reference purposes

__Namespace:__ _Sodium.ScalarMult_

```C#
public static int Bytes();
```

_Internally this function uses `sodium_scalarmult_base`._

```C#
public static int ScalarBytes();
```

_Internally this function uses `crypto_scalarmult_scalarbytes`._

```C#
public static byte[] Base(byte[] secretKey);
```

_Internally this function uses `crypto_scalarmult_base`._

```C#
public static byte[] Mult(byte[] secretKey, byte[] publicKey);
```

_Internally this function uses `crypto_scalarmult`._