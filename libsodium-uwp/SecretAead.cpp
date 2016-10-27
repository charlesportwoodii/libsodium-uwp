#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "SecretAead.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

// Generates a SecretAEAD Nonce
Array<unsigned char>^ Sodium::SecretAead::GenerateNonce()
{
	return Sodium::Core::GetRandomBytes(crypto_aead_chacha20poly1305_NPUBBYTES);
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(1);
	ad[0] = 0x00;

	return Sodium::SecretAead::Encrypt(message, nonce, key, ad);
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::SecretAead::Encrypt(Sodium::internal::StringToUnsignedCharArray(message), nonce, key);
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData)
{
	if (key->Length != crypto_aead_chacha20poly1305_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be " + crypto_aead_chacha20poly1305_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_aead_chacha20poly1305_NPUBBYTES) {
		throw ref new Platform::InvalidArgumentException("nonce must be " + crypto_aead_chacha20poly1305_NPUBBYTES + " bytes in length");
	}

	if (additionalData->Length > crypto_aead_chacha20poly1305_ABYTES || additionalData->Length < 0) {
		throw ref new Platform::InvalidArgumentException("additionalData must be " + additionalData->Length + " and " + crypto_aead_chacha20poly1305_ABYTES + " bytes in length");
	}

	Array<unsigned char>^ cipher = ref new Array<unsigned char>(message->Length + crypto_aead_chacha20poly1305_ABYTES);
	unsigned long long cipherLength;

	int result = crypto_aead_chacha20poly1305_encrypt(
		cipher->Data,
		&cipherLength,
		message->Data,
		message->Length,
		additionalData->Data,
		additionalData->Length,
		NULL,
		nonce->Data,
		key->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(result, "Failed to encrypt message");
	}

	if (cipher->Length == cipherLength) {
		return cipher;
	}

	Array<unsigned char>^ final = ref new Array<unsigned char>(cipherLength);
	memcpy(final->Data, cipher->Data, cipherLength);
	return final;
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData)
{
	return Sodium::SecretAead::Encrypt(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		key,
		additionalData
	);
}

Array<unsigned char>^ Sodium::SecretAead::Decrypt(const Array<unsigned char>^ encrypted, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(1);
	ad[0] = 0x00;

	return Sodium::SecretAead::Decrypt(encrypted, nonce, key, ad);
}

Array<unsigned char>^ Sodium::SecretAead::Decrypt(const Array<unsigned char>^ encrypted, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData)
{
	if (key->Length != crypto_aead_chacha20poly1305_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be " + crypto_aead_chacha20poly1305_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_aead_chacha20poly1305_NPUBBYTES) {
		throw ref new Platform::InvalidArgumentException("nonce must be " + crypto_aead_chacha20poly1305_NPUBBYTES + " bytes in length");
	}

	if (additionalData->Length > crypto_aead_chacha20poly1305_ABYTES || additionalData->Length < 0) {
		throw ref new Platform::InvalidArgumentException("additionalData must be " + additionalData->Length + " and " + crypto_aead_chacha20poly1305_ABYTES + " bytes in length");
	}

	Array<unsigned char>^ message = ref new Array<unsigned char>(encrypted->Length - crypto_aead_chacha20poly1305_ABYTES);
	unsigned long long messageLength;

	int result = crypto_aead_chacha20poly1305_decrypt(
		message->Data,
		&messageLength,
		NULL,
		encrypted->Data,
		encrypted->Length,
		additionalData->Data,
		additionalData->Length,
		nonce->Data,
		key->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(result, "Failed to dencrypt message");
	}

	if (message->Length == messageLength) {
		return message;
	}

	Array<unsigned char>^ final = ref new Array<unsigned char>(messageLength);
	memcpy(final->Data, message->Data, messageLength);
	return final;
}