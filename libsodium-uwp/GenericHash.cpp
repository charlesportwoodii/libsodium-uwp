#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "GenericHash.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

Array<unsigned char>^ Sodium::GenericHash::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_generichash_KEYBYTES_MAX);
}

Array<unsigned char>^ Sodium::GenericHash::Hash(const Array<unsigned char>^ message, const Array<unsigned char>^ key, int bytes)
{
	// Validate key length
	if (key == nullptr || key->Length == 0) {
		key = nullptr;
	} else {
		if (key->Length > crypto_generichash_KEYBYTES_MAX || key->Length < crypto_generichash_KEYBYTES_MIN) {
			throw ref new Platform::InvalidArgumentException("Key must be between " + crypto_generichash_KEYBYTES_MIN + " and " + crypto_generichash_KEYBYTES_MAX + " bytes in length");
		}
	}

	if (bytes > crypto_generichash_BYTES_MAX || bytes < crypto_generichash_BYTES_MIN) {
		throw ref new Platform::InvalidArgumentException("Bytes must be between " + crypto_generichash_BYTES_MIN + " and " + crypto_generichash_BYTES_MAX + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(bytes);
	int result = crypto_generichash(
		buffer->Data,
		buffer->Length,
		message->Data,
		message->Length,
		(key == nullptr ? NULL : key->Data),
		(key == nullptr ? 0 : key->Length)
	);

	return buffer;
}

Array<unsigned char>^ Sodium::GenericHash::Hash(String^ message, const Array<unsigned char>^ key, int bytes)
{
	return Sodium::GenericHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message),
		key,
		bytes
	);
}

Array<unsigned char>^ Sodium::GenericHash::Hash(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	return Sodium::GenericHash::Hash(
		message,
		key,
		crypto_generichash_BYTES
	);
}

Array<unsigned char>^ Sodium::GenericHash::Hash(String^ message, const Array<unsigned char>^ key)
{
	return Sodium::GenericHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message),
		key,
		crypto_generichash_BYTES
	);
}

Array<unsigned char>^ Sodium::GenericHash::Hash(const Array<unsigned char>^ message)
{
	return Sodium::GenericHash::Hash(
		message,
		nullptr,
		crypto_generichash_BYTES
	);
}

Array<unsigned char>^ Sodium::GenericHash::Hash(String^ message)
{
	return Sodium::GenericHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message),
		nullptr,
		crypto_generichash_BYTES
	);
}
