#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "SealedPublicKeyBox.h"
#include "KeyPair.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <summary>Creates a sealed public key box</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="recipientPublicKey">A 32 byte key</param>
/// <returns>The encrypted message</returns>
Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(const Array<unsigned char>^ message, const Array<unsigned char>^ recipientPublicKey)
{
	if (recipientPublicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Recipient public key must be " + crypto_box_PUBLICKEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(message->Length + crypto_box_SEALBYTES);
	int result = crypto_box_seal(
		buffer->Data,
		message->Data,
		message->Length,
		recipientPublicKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to create SealedPublicKeyBox");
}

/// <summary>Creates a sealed public key box</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="recipientPublicKey">A 32 byte key</param>
/// <returns>The encrypted message</returns>
Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(String^ message, const Array<unsigned char>^ recipientPublicKey)
{
	return Sodium::SealedPublicKeyBox::Create(
		Sodium::internal::StringToUnsignedCharArray(message),
		recipientPublicKey
	);
}

/// <summary>Creates a sealed public key box</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="recipientKeyPair">A KeyPair containing the public key</param>
/// <returns>The encrypted message</returns>
Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(const Array<unsigned char>^ message, KeyPair^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(
		message,
		recipientKeyPair->Public
	);
}

/// <summary>Creates a sealed public key box</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="recipientKeyPair">A KeyPair containing the public key</param>
/// <returns>The encrypted message</returns>
Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(String^ message, KeyPair^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(
		Sodium::internal::StringToUnsignedCharArray(message),
		recipientKeyPair
	);
}

/// <summary>Opens a sealed public key box</summary>
/// <param name="cipherText">The cipherTect to decrypt</param>
/// <param name="recipientSecretKey">The recipient secret key</param>
/// <param name="recipientPublicKey">The recipient public key</param>
/// <returns>The dencrypted message</returns>
Array<unsigned char>^ Sodium::SealedPublicKeyBox::Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ recipientSecretKey, const Array<unsigned char>^ recipientPublicKey)
{
	if (recipientPublicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Recipient public key must be " + crypto_box_PUBLICKEYBYTES + "bytes in length");
	}

	if (recipientSecretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Recipient secret key must be " + crypto_box_SECRETKEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(cipherText->Length - crypto_box_SEALBYTES);

	int result = crypto_box_seal_open(
		buffer->Data,
		cipherText->Data,
		cipherText->Length,
		recipientPublicKey->Data,
		recipientSecretKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to open SealedPublicKeyBox");
}

/// <summary>Opens a sealed public key box</summary>
/// <param name="cipherText">The cipherTect to decrypt</param>
/// <param name="recipientKeyair">The recipient key pair</param>
/// <returns>The dencrypted message</returns>
Array<unsigned char>^ Sodium::SealedPublicKeyBox::Open(const Array<unsigned char>^ cipherText, KeyPair^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(cipherText, recipientKeyPair->Public);
}
