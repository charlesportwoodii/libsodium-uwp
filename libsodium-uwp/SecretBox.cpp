#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "SecretBox.h"
#include "DetachedBox.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

// Generates a SecretBox Nonce
Array<unsigned char>^ Sodium::SecretBox::GenerateNonce()
{
	return Sodium::Core::GetRandomBytes(crypto_secretbox_NONCEBYTES);
}

// Returns a SecretBox key
Array<unsigned char>^ Sodium::SecretBox::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_secretbox_KEYBYTES);
}

Array<unsigned char>^ Sodium::SecretBox::Create(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::SecretBox::Create(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		key
	);
}

// Generates an encrypted message using a key and nonce
Array<unsigned char>^ Sodium::SecretBox::Create(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_secretbox_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_secretbox_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_secretbox_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_secretbox_NONCEBYTES + " bytes in length");
	}

	int cipherLength = crypto_secretbox_MACBYTES + message->Length;
	Array<unsigned char>^ cipherText = ref new Array<unsigned char>(cipherLength);
	int result = crypto_secretbox_easy(
		cipherText->Data,
		message->Data,
		message->Length,
		nonce->Data,
		key->Data
	);

	if (result == 0) {
		return cipherText;
	}

	throw ref new Platform::Exception(result, "Unable to create SecretBox");
}

// Decrypts an encrypted string using a key and nonce
Array<unsigned char>^ Sodium::SecretBox::Open(const Array<unsigned char>^ ciphertext, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_secretbox_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_secretbox_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_secretbox_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_secretbox_NONCEBYTES + " bytes in length");
	}

	int cipherLength = ciphertext->Length - crypto_secretbox_MACBYTES;
	Array<unsigned char>^ message = ref new Array<unsigned char>(cipherLength);
	int result = crypto_secretbox_open_easy(
		message->Data,
		ciphertext->Data,
		ciphertext->Length,
		nonce->Data,
		key->Data
	);

	if (result == 0) {
		return message;
	}

	throw ref new Platform::Exception(result, "Unable to open SecretBox.");
}

DetachedBox^ Sodium::SecretBox::CreateDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_secretbox_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be " + crypto_secretbox_KEYBYTES + "bytes in length");
	}

	if (nonce->Length != crypto_secretbox_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("nonce must be " + crypto_secretbox_NONCEBYTES + "bytes in length");
	}

	Array<unsigned char>^ cipher = ref new Array<unsigned char>(message->Length);
	Array<unsigned char>^ mac = ref new Array<unsigned char>(crypto_secretbox_MACBYTES);

	int result = crypto_secretbox_detached(
		cipher->Data,
		mac->Data,
		message->Data,
		message->Length,
		nonce->Data,
		key->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Failed to create detached SecretBox");
	}

	return ref new DetachedBox(cipher, mac);
}

DetachedBox^ Sodium::SecretBox::CreateDetached(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::SecretBox::CreateDetached(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		key
	);
}

Array<unsigned char>^ Sodium::SecretBox::OpenDetached(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_secretbox_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be " + crypto_secretbox_KEYBYTES + "bytes in length");
	}

	if (nonce->Length != crypto_secretbox_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("nonce must be " + crypto_secretbox_NONCEBYTES + "bytes in length");
	}

	if (mac->Length != crypto_secretbox_MACBYTES) {
		throw ref new Platform::InvalidArgumentException("mac must be " + crypto_secretbox_MACBYTES + "bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(cipherText->Length);
	int result = crypto_secretbox_open_detached(
		buffer->Data,
		cipherText->Data,
		mac->Data,
		cipherText->Length,
		nonce->Data,
		key->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Failed top open detached secret box");
	}

	return buffer;
}

Array<unsigned char>^ Sodium::SecretBox::OpenDetached(String^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::SecretBox::OpenDetached(
		Sodium::internal::StringToUnsignedCharArray(cipherText),
		mac,
		nonce,
		key
	);
}

Array<unsigned char>^ Sodium::SecretBox::OpenDetached(DetachedBox^ detached, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::SecretBox::OpenDetached(
		detached->Cipher,
		detached->Mac,
		nonce,
		key
	);
}