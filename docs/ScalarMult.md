# Scalar Multiplication

The following internal functions are exposed and documented for reference purposes

__Namespace:__ _Sodium.ScalarMult_

```C#
static int Bytes();
```

_Internally this function uses `sodium_scalarmult_base`._

```C#
static int ScalarBytes();
```

_Internally this function uses `crypto_scalarmult_scalarbytes`._

```C#
static Array<unsigned char>^ Base(const Array<unsigned char>^ secretKey);
```

_Internally this function uses `crypto_scalarmult_base`._

```C#
static Array<unsigned char>^ Mult(const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
```

_Internally this function uses `crypto_scalarmult`._