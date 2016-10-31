#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "CryptoHash.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <summary>Calculates the SHA256 hash of the given input</summary>
/// <param name="message">The message to generate a hash for</param>
/// <returns>32 byte SHA256 hash of message</returns>
Array<unsigned char>^ Sodium::CryptoHash::Sha256(const Array<unsigned char>^ message)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_hash_sha256_BYTES);
	int result = crypto_hash_sha256(
		buffer->Data,
		message->Data,
		message->Length
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Unable to generate Sha256 hash");
}

/// <see ref="Sodium::CryptoHash:Sha256"></see>
Array<unsigned char>^ Sodium::CryptoHash::Sha256(String^ message)
{
	return Sodium::CryptoHash::Sha256(
		Sodium::internal::StringToUnsignedCharArray(message)
	);
}

/// <summary>Calculates the SHA512 hash of the given input</summary>
/// <param name="message">The message to generate a hash for</param>
/// <returns>64 byte SHA512 hash of message</returns>
Array<unsigned char>^ Sodium::CryptoHash::Sha512(const Array<unsigned char>^ message)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_hash_sha512_BYTES);
	int result = crypto_hash_sha512(
		buffer->Data,
		message->Data,
		message->Length
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Unable to generate Sha512 hash");
}

/// <see ref="Sodium::CryptoHash:Sha512"></see>
Array<unsigned char>^ Sodium::CryptoHash::Sha512(String^ message)
{
	return Sodium::CryptoHash::Sha512(
		Sodium::internal::StringToUnsignedCharArray(message)
	);
}

/// <summary>Calculates a hash of the given message using the default hashing algorithm in libsodium (SHA512)</summary>
/// <param name="message">The message to generate a hash for</param>
/// <returns>64 byte SHA512 hash of message</returns>
Array<unsigned char>^ Sodium::CryptoHash::Hash(const Array<unsigned char>^ message)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_hash_sha512_BYTES);
	int result = crypto_hash(
		buffer->Data,
		message->Data,
		message->Length
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Unable to generate Sha512 hash");
}

/// <see ref="Sodium::CryptoHash:Hash"></see>
Array<unsigned char>^ Sodium::CryptoHash::Hash(String^ message)
{
	return Sodium::CryptoHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message)
	);
}
