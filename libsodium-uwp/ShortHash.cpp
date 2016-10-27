#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "ShortHash.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

Array<unsigned char>^ Sodium::ShortHash::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_shorthash_KEYBYTES);
}

Array<unsigned char>^ Sodium::ShortHash::Hash(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_shorthash_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be " + crypto_shorthash_KEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_shorthash_BYTES);

	int result = crypto_shorthash(
		buffer->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return buffer;
}

Array<unsigned char>^ Sodium::ShortHash::Hash(String^ message, const Array<unsigned char>^ key)
{
	return Sodium::ShortHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message),
		key
	);
}

Array<unsigned char>^ Sodium::ShortHash::Hash(String^ message, String^ key)
{
	return Sodium::ShortHash::Hash(
		message,
		Sodium::internal::StringToUnsignedCharArray(key)
	);
}