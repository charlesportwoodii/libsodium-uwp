#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "PublicKeyAuth.h"
#include "KeyPair.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

// Generates a PublicKeyAuth KeyPair
KeyPair ^ Sodium::PublicKeyAuth::GenerateKeyPair()
{
	KeyPair^ kp = ref new KeyPair();
	kp->Public = ref new Array<unsigned char>(crypto_sign_PUBLICKEYBYTES);
	kp->Secret = ref new Array<unsigned char>(crypto_sign_SECRETKEYBYTES);

	crypto_sign_keypair(kp->Public->Data, kp->Secret->Data);

	return kp;
}

// Generates a PublicKeyAuth KeyPair from a seed.
KeyPair ^ Sodium::PublicKeyAuth::GenerateKeyPair(const Array<unsigned char>^ seed)
{
	KeyPair^ kp = ref new KeyPair();
	if (seed->Length != crypto_sign_SEEDBYTES) {
		throw ref new Platform::InvalidArgumentException("Seed must be " + crypto_sign_SEEDBYTES + " bytes");
	}

	kp->Public = ref new Array<unsigned char>(crypto_sign_PUBLICKEYBYTES);
	kp->Secret = ref new Array<unsigned char>(crypto_sign_SECRETKEYBYTES);
	crypto_sign_seed_keypair(kp->Public->Data, kp->Secret->Data, seed->Data);

	return kp;
}

// Signs a message given a private key
Array<unsigned char>^ Sodium::PublicKeyAuth::Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ privateKey)
{
	if (privateKey->Length != crypto_sign_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_sign_SECRETKEYBYTES + " bytes in length");
	}

	unsigned long long bufferLength = 0;
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(message->Length + crypto_sign_BYTES);

	int result = crypto_sign(
		buffer->Data,
		&bufferLength,
		message->Data,
		message->Length,
		privateKey->Data
	);

	if (result == 0) {
		Array<unsigned char>^ final = ref new Array<unsigned char>(bufferLength);
		memcpy(final->Data, buffer->Data, bufferLength);
		return final;
	}

	throw ref new Platform::Exception(result, "Failed to sign message");
}

Array<unsigned char>^ Sodium::PublicKeyAuth::Sign(String ^ message, const Array<unsigned char>^ privateKey)
{
	return Sodium::PublicKeyAuth::Sign(
		Sodium::internal::StringToUnsignedCharArray(message),
		privateKey
	);
}

// Verifies a signature with a public key
Array<unsigned char>^ Sodium::PublicKeyAuth::Verify(const Array<unsigned char>^ signedMessage, const Array<unsigned char>^ publicKey)
{
	if (publicKey->Length != crypto_sign_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_sign_PUBLICKEYBYTES + " bytes in length");
	}

	unsigned long long bufferLength = 0;
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(signedMessage->Length);

	int result = crypto_sign_open(
		buffer->Data,
		&bufferLength,
		signedMessage->Data,
		signedMessage->Length,
		publicKey->Data
	);

	if (result == 0) {
		Array<unsigned char>^ final = ref new Array<unsigned char>(bufferLength);
		memcpy(final->Data, buffer->Data, bufferLength);
		return final;
	}

	throw ref new Platform::Exception(result, "Failed to verify signature");
}

// Converts an ED25519 Public Key to a Curve25519 Public Key
Array<unsigned char>^ Sodium::PublicKeyAuth::ConvertEd25519PublicKeyToCurve25519PublicKey(const Array<unsigned char>^ publicKey)
{
	if (publicKey->Length != crypto_sign_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("ed25519PublicKey must " + crypto_sign_PUBLICKEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_box_PUBLICKEYBYTES);

	int result = crypto_sign_ed25519_pk_to_curve25519(
		buffer->Data,
		publicKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to convert public key");
}

// Converts a Ed25519 Private Key to a Curve25519 Private Key
Array<unsigned char>^ Sodium::PublicKeyAuth::ConvertEd25519SecretKeyToCurve25519SecretKey(const Array<unsigned char>^ privateKey)
{
	if (privateKey->Length != crypto_sign_PUBLICKEYBYTES && privateKey->Length != crypto_sign_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Secret key must be either " + crypto_sign_PUBLICKEYBYTES + " or " + crypto_sign_SECRETKEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_box_SECRETKEYBYTES);

	int result = crypto_sign_ed25519_sk_to_curve25519(
		buffer->Data,
		privateKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to convert private key");
}

Array<unsigned char>^ Sodium::PublicKeyAuth::SignDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ secretKey)
{
	if (secretKey->Length != crypto_sign_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("secretKey must be " + crypto_sign_SECRETKEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ signature = ref new Array<unsigned char>(crypto_sign_BYTES);
	unsigned long long signatureLength = 0;

	int result = crypto_sign_detached(
		signature->Data,
		&signatureLength,
		message->Data,
		message->Length,
		secretKey->Data
	);

	return signature;
}

Array<unsigned char>^ Sodium::PublicKeyAuth::SignDetached(String^ message, const Array<unsigned char>^ secretKey)
{
	return Sodium::PublicKeyAuth::SignDetached(
		Sodium::internal::StringToUnsignedCharArray(message),
		secretKey
	);
}

bool Sodium::PublicKeyAuth::VerifyDetached(const Array<unsigned char>^ signature, const Array<unsigned char>^ message, const Array<unsigned char>^ publicKey)
{
	if (signature->Length != crypto_sign_BYTES) {
		throw ref new Platform::InvalidArgumentException("Signature must be " + crypto_sign_BYTES + " bytes in length");
	}

	if (publicKey->Length != crypto_sign_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("publicKey must be " + crypto_sign_PUBLICKEYBYTES + " bytes in length");
	}

	int result = crypto_sign_verify_detached(
		signature->Data,
		message->Data,
		message->Length,
		publicKey->Data
	);

	return result == 0;
}

bool Sodium::PublicKeyAuth::VerifyDetached(const Array<unsigned char>^ signature, String ^ message, const Array<unsigned char>^ publicKey)
{
	return Sodium::PublicKeyAuth::VerifyDetached(
		signature,
		Sodium::internal::StringToUnsignedCharArray(message),
		publicKey
	);
}

Array<unsigned char>^ Sodium::PublicKeyAuth::ExtractEd25519SeedFromEd25519SecretKey(const Array<unsigned char>^ ed25519SecretKey)
{
	if (ed25519SecretKey->Length != crypto_sign_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("ed25519SecretKey must be " + crypto_sign_PUBLICKEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_sign_SEEDBYTES);

	int result = crypto_sign_ed25519_sk_to_seed(
		buffer->Data,
		ed25519SecretKey->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Failed to extract seed from secret key");
	}

	return buffer;
}

Array<unsigned char>^ Sodium::PublicKeyAuth::ExtractEd25519PublicKeyFromEd25519SecretKey(const Array<unsigned char>^ ed25519SecretKey)
{
	if (ed25519SecretKey->Length != crypto_sign_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("ed25519SecretKey must be " + crypto_sign_PUBLICKEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_sign_PUBLICKEYBYTES);

	int result = crypto_sign_ed25519_sk_to_pk(
		buffer->Data,
		ed25519SecretKey->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Failed to extract public key from secret key");
	}

	return buffer;
}
