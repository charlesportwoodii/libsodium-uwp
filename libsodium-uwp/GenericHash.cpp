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


/// <summary>Appends data to the generic hash state</summary>
/// <param name="data">The data to append</param>
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

/// <summary>Finalizes the generic hash state</summary>
/// <returns>Returns the hash with the originally request length</returns>
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

/// <returns>64 byte key</returns>
Array<unsigned char>^ Sodium::GenericHash::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_generichash_KEYBYTES_MAX);
}

/// <summary>Hashes a message with Blake2</summary>
/// <param name="message">The message to hash</param>
/// <param name="key">The key to hash the message with</param>
/// <param name="bytes">The length of the hash</param>
/// <returns>A generic hash, bytes length in bytes</returns>
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


/// <summary>Hashes a message with Blake2</summary>
/// <param name="message">The message to hash</param>
/// <param name="key">The key to hash the message with</param>
/// <param name="bytes">The length of the hash</param>
/// <returns>A generic hash, bytes length in bytes</returns>
Array<unsigned char>^ Sodium::GenericHash::Hash(String^ message, const Array<unsigned char>^ key, int bytes)
{
	return Sodium::GenericHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message),
		key,
		bytes
	);
}

/// <summary>Hashes a message with Blake2</summary>
/// <param name="message">The message to hash</param>
/// <param name="key">The key to hash the message with</param>
/// <returns>32 byte hash</returns>
Array<unsigned char>^ Sodium::GenericHash::Hash(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	return Sodium::GenericHash::Hash(
		message,
		key,
		crypto_generichash_BYTES
	);
}

/// <summary>Hashes a message with Blake2</summary>
/// <param name="message">The message to hash</param>
/// <param name="key">The key to hash the message with</param>
/// <returns>32 byte hash</returns>
Array<unsigned char>^ Sodium::GenericHash::Hash(String^ message, const Array<unsigned char>^ key)
{
	return Sodium::GenericHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message),
		key,
		crypto_generichash_BYTES
	);
}

/// <summary>Hashes a message with Blake2</summary>
/// <param name="message">The message to hash</param>
/// <returns>32 byte hash</returns>
Array<unsigned char>^ Sodium::GenericHash::Hash(const Array<unsigned char>^ message)
{
	return Sodium::GenericHash::Hash(
		message,
		nullptr,
		crypto_generichash_BYTES
	);
}

/// <summary>Hashes a message with Blake2</summary>
/// <param name="message">The message to hash</param>
/// <returns>32 byte hash</returns>
Array<unsigned char>^ Sodium::GenericHash::Hash(String^ message)
{
	return Sodium::GenericHash::Hash(
		Sodium::internal::StringToUnsignedCharArray(message),
		nullptr,
		crypto_generichash_BYTES
	);
}

/// <summary>Opens the specified algorithm for use with GenericHash</summary>
/// <param name="algorithm">The selected algorithm for GenericHashAlgorithmProvider</param>
/// <returns>A new GenericHashAlgorithmProvider instance with the provided algorithm</returns>
GenericHashAlgorithmProvider^ Sodium::GenericHashAlgorithmProvider::OpenAlgorithm(String^ algorithm)
{
	return ref new GenericHashAlgorithmProvider(algorithm);
}

/// <summary>Creates a new GenericHash object</summary>
/// <returns>Returns a GenericHashObject with a given key, set to 32 bytes in length</returns>
GenericHash^ Sodium::GenericHashAlgorithmProvider::CreateHash()
{
	return this->CreateHash(nullptr, crypto_generichash_BYTES);
}

/// <summary>Creates a new GenericHash object</summary>
/// <param name="key">The raw key data</param>
/// <returns>Returns a GenericHashObject with a null key, set to 32 bytes in length</returns>
GenericHash^ Sodium::GenericHashAlgorithmProvider::CreateHash(const Array<unsigned char>^ key)
{
	return this->CreateHash(key, crypto_generichash_BYTES);
}

/// <summary>Creates a new GenericHash object</summary>
/// <param name="key">The raw key data</param>
/// <param name="bytes">The number of bytes to use with Blake2</param>
/// <returns>Returns a GenericHashObject</returns>
GenericHash^ Sodium::GenericHashAlgorithmProvider::CreateHash(const Array<unsigned char>^ key, int bytes)
{
	return ref new GenericHash(key, bytes);
}
