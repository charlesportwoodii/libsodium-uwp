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


/// <summary>Appends data to the crypto sign state</summary>
/// <param name="data">The data to append</param>
void Sodium::PublicKeyAuth::Append(IBuffer^ data)
{
	Array<unsigned char>^ d = ref new Array<unsigned char>(data->Length);
	CryptographicBuffer::CopyToByteArray(data, &d);

	crypto_sign_state state;
	memcpy(&state, this->state->Data, this->state_len);

	int result = crypto_sign_update(
		&state,
		d->Data,
		d->Length
	);

	Array<unsigned char>^ s = ref new Array<unsigned char>(state_len);
	memcpy(s->Data, &state, state_len);

	this->state = s;
}

/// <summary>Gets the signature given the secret key</summary>
/// <param name="secretKey">The secret key</param>
/// <returns>The signature</returns>
Array<unsigned char>^ Sodium::PublicKeyAuth::GetValueAndReset(const Array<unsigned char>^ secretKey)
{
	Array<unsigned char>^ signature = ref new Array<unsigned char>(crypto_sign_BYTES);

	crypto_sign_state state;
	memcpy(&state, this->state->Data, this->state_len);

	int result = crypto_sign_final_create(
		&state,
		signature->Data,
		NULL,
		secretKey->Data
	);

	return signature;
}

/// <summary>Verifies the value of a signature given a publickey</summary>
/// <param name="signature">The signature</param>
/// <param name="publicKey">The public key</param>
/// <returns>Boolean</returns>
bool Sodium::PublicKeyAuth::GetValueAndVerify(const Array<unsigned char>^ signature, const Array<unsigned char>^ publicKey)
{
	crypto_sign_state state;
	memcpy(&state, this->state->Data, this->state_len);

	int result = crypto_sign_final_verify(
		&state,
		signature->Data,
		publicKey->Data
	);

	if (result == 0) {
		return true;
	}

	return false;
}

/// <summary>Generates a KeyPair</summary>
/// <returns>A KeyPair object</returns>
KeyPair ^ Sodium::PublicKeyAuth::GenerateKeyPair()
{
	KeyPair^ kp = ref new KeyPair();
	kp->Public = ref new Array<unsigned char>(crypto_sign_PUBLICKEYBYTES);
	kp->Secret = ref new Array<unsigned char>(crypto_sign_SECRETKEYBYTES);

	crypto_sign_keypair(kp->Public->Data, kp->Secret->Data);

	return kp;
}

/// <summary>Generates a PublicKeyAuth KeyPair from a seed</summary>
/// <param name="seed">A 32 byte seed</param>
/// <returns>A KeyPair object</returns>
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

/// <summary>Signs a message given a private key</summary>
/// <param name="message">The message to sign</param>
/// <param name="privateKey">64 byte ed25519 private key</param>
/// <returns>A signed message</returns>
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

/// <summary>Signs a message given a private key</summary>
/// <param name="message">The message to sign</param>
/// <param name="privateKey">64 byte ed25519 private key</param>
/// <returns>A signed message</returns>
Array<unsigned char>^ Sodium::PublicKeyAuth::Sign(String ^ message, const Array<unsigned char>^ privateKey)
{
	return Sodium::PublicKeyAuth::Sign(
		Sodium::internal::StringToUnsignedCharArray(message),
		privateKey
	);
}

/// <summary>Verifies a message signed by Sodium.PublicKeyAuth.Verify</summary>
/// <param name="signedMessage">The message to verify</param>
/// <param name="privateKey">32 byte ed25519 private key</param>
/// <returns>The original message</returns>
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

/// <summary>Converts an ED25519 Public Key to a Curve25519 Public Key</summary>
/// <param name="publicKey">32 byte ed25519 public key</param>
/// <returns>32 byte Curve25519 public key</returns>
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

/// <summary>Converts a Ed25519 Private Key to a Curve25519 Private Key</summary>
/// <param name="privateKey">64 byte ed25519 private key</param>
/// <returns>32 byte Curve25519 private key</returns>
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

/// <summary>Signs a message given a private key in detached mode</summary>
/// <param name="message">The message to sign</param>
/// <param name="secretKey">64 byte ed25519 private key</param>
/// <returns>A signed message</returns>
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

/// <summary>Signs a message given a private key in detached mode</summary>
/// <param name="message">The message to sign</param>
/// <param name="secretKey">64 byte ed25519 private key</param>
/// <returns>A signed message</returns>
Array<unsigned char>^ Sodium::PublicKeyAuth::SignDetached(String^ message, const Array<unsigned char>^ secretKey)
{
	return Sodium::PublicKeyAuth::SignDetached(
		Sodium::internal::StringToUnsignedCharArray(message),
		secretKey
	);
}

/// <summary>Verifies a message signed by Sodium.PublicKeyAuth.CreateDetached</summary>
/// <param name="signature">A 16 byte signature</param>
/// <param name="message">The message to verify</param>
/// <param name="privateKey">32 byte public key</param>
/// <returns>Returns true of the message is valid</returns>
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

/// <summary>Verifies a message signed by Sodium.PublicKeyAuth.CreateDetached</summary>
/// <param name="signature">A 16 byte signature</param>
/// <param name="message">The message to verify</param>
/// <param name="privateKey">32 byte public key</param>
/// <returns>Returns true of the message is valid</returns>
bool Sodium::PublicKeyAuth::VerifyDetached(const Array<unsigned char>^ signature, String^ message, const Array<unsigned char>^ publicKey)
{
	return Sodium::PublicKeyAuth::VerifyDetached(
		signature,
		Sodium::internal::StringToUnsignedCharArray(message),
		publicKey
	);
}

/// <summary>Extracts an ed25519 seed from an ed25519 secret key</summary>
/// <param name="ed25519SecretKey">64 byte ed25519 private key</param>
/// <returns>32 byte seed</returns>
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

/// <summary>Extracts an ed25519 public key from an ed25519 secret key</summary>
/// <param name="ed25519SecretKey">64 byte ed25519 private key</param>
/// <returns>32 byte public key</returns>
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
