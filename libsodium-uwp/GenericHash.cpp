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

void Sodium::GenericHash::Append(IBuffer^ data)
{	
	Array<unsigned char>^ d = ref new Array<unsigned char>(data->Length);
	CryptographicBuffer::CopyToByteArray(data, &d);

	crypto_generichash_state state;
	memcpy(&state, this->state->Data, this->state_len);

	int result = crypto_generichash_update(
		&state,
		d->Data,
		d->Length
	);

	Array<unsigned char>^ s = ref new Array<unsigned char>(state_len);
	memcpy(s->Data, &state, state_len);

	this->state = s;
}

Array<unsigned char>^ Sodium::GenericHash::GetValueAndReset()
{
	Array<unsigned char>^ hash = ref new Array<unsigned char>(this->bytes);

	crypto_generichash_state state;
	memcpy(&state, this->state->Data, this->state_len);

	int result = crypto_generichash_final(
		&state,
		hash->Data,
		hash->Length
	);

	return hash;
}

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

GenericHashAlgorithmProvider^ Sodium::GenericHashAlgorithmProvider::OpenAlgorithm(String^ algorithm)
{
	return ref new GenericHashAlgorithmProvider(algorithm);
}

GenericHash^ Sodium::GenericHashAlgorithmProvider::CreateHash()
{
	return this->CreateHash(nullptr, crypto_generichash_BYTES);
}

GenericHash^ Sodium::GenericHashAlgorithmProvider::CreateHash(const Array<unsigned char>^ key)
{
	return this->CreateHash(key, crypto_generichash_BYTES);
}

GenericHash^ Sodium::GenericHashAlgorithmProvider::CreateHash(const Array<unsigned char>^ key, int bytes)
{
	return ref new GenericHash(key, bytes);
}
