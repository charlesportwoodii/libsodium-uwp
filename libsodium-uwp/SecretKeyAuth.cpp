#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "SecretKeyAuth.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

// Generates a 32 byte SecretKeyAuth key
Array<unsigned char>^ Sodium::SecretKeyAuth::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_auth_KEYBYTES);
}

// Creates a secret key auth signature
Array<unsigned char>^ Sodium::SecretKeyAuth::Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_auth_KEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ signature = ref new Array<unsigned char>(crypto_auth_KEYBYTES);
	int result = crypto_auth(
		signature->Data,
		message->Data,
		message->Length,
		key->Data
	);

	if (result == 0) {
		return signature;
	}

	throw ref new Platform::Exception(result, "Unable to generate signature");
}

Array<unsigned char>^ Sodium::SecretKeyAuth::Sign(String ^ message, const Array<unsigned char>^ key)
{
	return Sodium::SecretKeyAuth::Sign(
		Sodium::internal::StringToUnsignedCharArray(message),
		key
	);
}

// Verifies a secret key auth signature
bool Sodium::SecretKeyAuth::Verify(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_auth_KEYBYTES + " bytes in length");
	}

	if (signature->Length != crypto_auth_BYTES) {
		throw ref new Platform::InvalidArgumentException("Signature must be " + crypto_auth_BYTES + " bytes in length");
	}

	int result = crypto_auth_verify(
		signature->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return result == 0;
}

bool Sodium::SecretKeyAuth::Verify(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	return Sodium::SecretKeyAuth::Verify(
		Sodium::internal::StringToUnsignedCharArray(message),
		signature,
		key
	);
}

Array<unsigned char>^ Sodium::SecretKeyAuth::SignHmacSha256(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_hmacsha256_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_auth_hmacsha256_KEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_auth_hmacsha256_BYTES);
	int result = crypto_auth_hmacsha256(
		buffer->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return buffer;
}

Array<unsigned char>^ Sodium::SecretKeyAuth::SignHmacSha256(String^ message, const Array<unsigned char>^ key)
{
	return Sodium::SecretKeyAuth::SignHmacSha256(
		Sodium::internal::StringToUnsignedCharArray(message),
		key
	);
}

bool Sodium::SecretKeyAuth::VerifyHmacSha256(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_hmacsha256_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_auth_hmacsha256_KEYBYTES + " bytes in length");
	}

	if (signature->Length != crypto_auth_hmacsha256_BYTES) {
		throw ref new Platform::InvalidArgumentException("Signature must be " + crypto_auth_hmacsha256_BYTES + " bytes in length");
	}

	int result = crypto_auth_hmacsha256_verify(
		signature->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return result == 0;
}

bool Sodium::SecretKeyAuth::VerifyHmacSha256(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	return Sodium::SecretKeyAuth::VerifyHmacSha256(
		Sodium::internal::StringToUnsignedCharArray(message),
		signature,
		key
	);
}

Array<unsigned char>^ Sodium::SecretKeyAuth::SignHmacSha512(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_hmacsha256_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_auth_hmacsha256_KEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_auth_hmacsha512_BYTES);
	int result = crypto_auth_hmacsha512(
		buffer->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return buffer;
}

Array<unsigned char>^ Sodium::SecretKeyAuth::SignHmacSha512(String ^ message, const Array<unsigned char>^ key)
{
	return Sodium::SecretKeyAuth::SignHmacSha512(
		Sodium::internal::StringToUnsignedCharArray(message),
		key
	);
}

bool Sodium::SecretKeyAuth::VerifyHmacSha512(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_hmacsha512_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_auth_hmacsha512_KEYBYTES + " bytes in length");
	}

	if (signature->Length != crypto_auth_hmacsha512_BYTES) {
		throw ref new Platform::InvalidArgumentException("Signature must be " + crypto_auth_hmacsha512_BYTES + " bytes in length");
	}

	int result = crypto_auth_hmacsha512_verify(
		signature->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return result == 0;
}

bool Sodium::SecretKeyAuth::VerifyHmacSha512(String ^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	return Sodium::SecretKeyAuth::VerifyHmacSha512(
		Sodium::internal::StringToUnsignedCharArray(message),
		signature,
		key
	);
}