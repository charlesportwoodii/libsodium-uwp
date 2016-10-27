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

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(String^ message, const Array<unsigned char>^ recipientPublicKey)
{
	return Sodium::SealedPublicKeyBox::Create(
		Sodium::internal::StringToUnsignedCharArray(message),
		recipientPublicKey
	);
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(const Array<unsigned char>^ message, KeyPair^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(message, recipientKeyPair->Public);
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(String^ message, KeyPair^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(
		Sodium::internal::StringToUnsignedCharArray(message),
		recipientKeyPair
	);
}

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


Array<unsigned char>^ Sodium::SealedPublicKeyBox::Open(const Array<unsigned char>^ cipherText, KeyPair^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(cipherText, recipientKeyPair->Public);
}
