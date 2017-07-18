#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "PublicKeyBox.h"
#include "KeyPair.h"
#include "DetachedBox.h"
#include "ScalarMult.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <see>Sodium.Core.GetRandomBytes</see>
/// <returns>24 byte nonce</returns>
Array<unsigned char>^ Sodium::PublicKeyBox::GenerateNonce()
{
	return Sodium::Core::GetRandomBytes(crypto_box_NONCEBYTES);
}

/// <summary>Generates a crypto_box key pair</summary>
/// <returns>A KeyPair object</returns>
KeyPair^ Sodium::PublicKeyBox::GenerateKeyPair()
{
	KeyPair^ kp = ref new KeyPair();
	kp->Public = ref new Array<unsigned char>(crypto_box_PUBLICKEYBYTES);
	kp->Secret = ref new Array<unsigned char>(crypto_box_SECRETKEYBYTES);

	crypto_box_keypair(kp->Public->Data, kp->Secret->Data);

	return kp;
}

/// <summary>Generates a keypair from a private key</summary>
/// <param name="privateKey">Byte representation of the private key</param>
/// <returns>A KeyPair object</returns>
KeyPair^ Sodium::PublicKeyBox::GenerateKeyPair(const Array<unsigned char>^ privateKey)
{
	KeyPair^ kp = ref new KeyPair();
	if (privateKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must be " + crypto_box_SECRETKEYBYTES + " bytes");
	}

	kp->Secret = privateKey;
	kp->Public = Sodium::ScalarMult::Base(kp->Secret);

	return kp;
}

/// <summary>Encrypts a message using crypto_box_easy</summary>
/// <param name="message">The byte message to be encrypted</param>
/// <param name="nonce">A unique nonce for this message</param>
/// <param name="secretKey">The senders private key</param>
/// <param name="publicKey">The recipients public key</param>
/// <returns>An encrypted byte array</returns>
Array<unsigned char>^ Sodium::PublicKeyBox::Create(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must " + crypto_box_SECRETKEYBYTES + " bytes in length");
	}

	if (publicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Public key must " + crypto_box_PUBLICKEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_box_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_box_NONCEBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(message->Length + crypto_box_MACBYTES);
	int result = crypto_box_easy(
		buffer->Data,
		message->Data,
		message->Length,
		nonce->Data,
		publicKey->Data,
		secretKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to create PublicKeyBox");
}

/// <summary>Encrypts a message using crypto_box_easy</summary>
/// <param name="message">The string message to be encrypted</param>
/// <param name="nonce">A unique nonce for this message</param>
/// <param name="secretKey">The senders private key</param>
/// <param name="publicKey">The recipients public key</param>
/// <returns>An encrypted byte array</returns>
/// <see>Sodium.PublicKeyBox.Create</see>
Array<unsigned char>^ Sodium::PublicKeyBox::Create(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	return Sodium::PublicKeyBox::Create(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		secretKey,
		publicKey
	);
}

/// <summary>Decrypts a cipherText using crypto_box_open_easy</summary>
/// <param name="cipherText">The byte message to be encrypted</param>
/// <param name="nonce">A unique nonce for this message</param>
/// <param name="secretKey">The recipients private key</param>
/// <param name="publicKey">The senders public key</param>
/// <returns>An encrypted byte array</returns>
Array<unsigned char>^ Sodium::PublicKeyBox::Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must " + crypto_box_SECRETKEYBYTES + " bytes in length");
	}

	if (publicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Public key must " + crypto_box_PUBLICKEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_box_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_box_NONCEBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(cipherText->Length - crypto_box_MACBYTES);
	int result = crypto_box_open_easy(
		buffer->Data,
		cipherText->Data,
		cipherText->Length,
		nonce->Data,
		publicKey->Data,
		secretKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Unable to open PublicKeyBox");
}

/// <summary>Encrypts a message in detached mode</summary>
/// <param name="message">The byte message to be encrypted</param>
/// <param name="nonce">A unique nonce for this message</param>
/// <param name="secretKey">The senders private key</param>
/// <param name="publicKey">The recipients public key</param>
/// <returns>An encrypted byte array</returns>
DetachedBox ^ Sodium::PublicKeyBox::CreateDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must " + crypto_box_SECRETKEYBYTES + " bytes in length");
	}

	if (publicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Public key must " + crypto_box_PUBLICKEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_box_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_box_NONCEBYTES + " bytes in length");
	}

	Array<unsigned char>^ cipher = ref new Array<unsigned char>(message->Length);
	Array<unsigned char>^ mac = ref new Array<unsigned char>(crypto_box_MACBYTES);

	int result = crypto_box_detached(
		cipher->Data,
		mac->Data,
		message->Data,
		message->Length,
		nonce->Data,
		publicKey->Data,
		secretKey->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Failed to create public detached box");
	}

	return ref new DetachedBox(cipher, mac);
}

/// <summary>Encrypts a message in detached mode</summary>
/// <param name="message">The string message to be encrypted</param>
/// <param name="nonce">A unique nonce for this message</param>
/// <param name="secretKey">The senders private key</param>
/// <param name="publicKey">The recipients public key</param>
/// <returns>An encrypted byte array</returns>
/// <see>Sodium.PublicKeyBox.CreateDetached</see>
DetachedBox ^ Sodium::PublicKeyBox::CreateDetached(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	return Sodium::PublicKeyBox::CreateDetached(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		secretKey,
		publicKey
	);
}

/// <summary>Decrypts a cipherText in detached mode</summary>
/// <param name="cipherText">The byte message to be dencrypted</param>
/// <param name="mac">The message authentication code</param>
/// <param name="nonce">A unique nonce for this message</param>
/// <param name="secretKey">The recipients private key</param>
/// <param name="publicKey">The senders public key</param>
/// <returns>The decrypted message as a byte array</returns>
Array<unsigned char>^ Sodium::PublicKeyBox::OpenDetached(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must " + crypto_box_SECRETKEYBYTES + " bytes in length");
	}

	if (publicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Public key must " + crypto_box_PUBLICKEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_box_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_box_NONCEBYTES + " bytes in length");
	}

	if (mac->Length != crypto_box_MACBYTES) {
		throw ref new Platform::InvalidArgumentException("Mac must be " + crypto_box_MACBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(cipherText->Length);
	int result = crypto_box_open_detached(
		buffer->Data,
		cipherText->Data,
		mac->Data,
		cipherText->Length,
		nonce->Data,
		publicKey->Data,
		secretKey->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Failed to open public detached box");
	}

	return buffer;
}

/// <summary>Decrypts a cipherText in detached mode</summary>
/// <param name="cipherText">The string message to be dencrypted</param>
/// <param name="mac">The message authentication code</param>
/// <param name="nonce">A unique nonce for this message</param>
/// <param name="secretKey">The recipients private key</param>
/// <param name="publicKey">The senders public key</param>
/// <returns>The decrypted message as a byte array</returns>
Array<unsigned char>^ Sodium::PublicKeyBox::OpenDetached(String^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	return Sodium::PublicKeyBox::OpenDetached(
		Sodium::internal::StringToUnsignedCharArray(cipherText),
		mac,
		nonce,
		secretKey,
		publicKey
	);
}

/// <summary>Decrypts a cipherText in detached mode</summary>
/// <param name="detached">A DetachedBox instance that contains the cipherText and message</param>
/// <param name="secretKey">The recipients private key</param>
/// <param name="publicKey">The senders public key</param>
/// <returns>The decrypted message as a byte array</returns>
Array<unsigned char>^ Sodium::PublicKeyBox::OpenDetached(DetachedBox^ detached, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	return Sodium::PublicKeyBox::OpenDetached(
		detached->Cipher,
		detached->Mac,
		nonce,
		secretKey,
		publicKey
	);
}