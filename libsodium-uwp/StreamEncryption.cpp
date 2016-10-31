#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "StreamEncryption.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <summary>Private method used to encrypt a message using the selected method</summary>
/// <param name="data">The data to encrypt or decrypt</param>
/// <param name="nonce">The 24 or 8 byte nonce</param>
/// <param name="key">The 32 byte key</param>
/// <param name="method">The stream cipher to use (1=XSalsa20, 2=ChaCha20, 3=Salsa20)</param>
/// <returns>CipherText or plainText data</returns>
Array<unsigned char>^ Sodium::StreamEncryption::ProcessInternal(const Array<unsigned char>^ data, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, int method)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(data->Length);
	int result = -1;

	if (method == 1) { // XSALSA20
		result = crypto_stream_xsalsa20_xor(
			buffer->Data,
			data->Data,
			data->Length,
			nonce->Data,
			key->Data
		);
	}
	else if (method == 2) { // CHACHA20
		result = crypto_stream_chacha20_xor(
			buffer->Data,
			data->Data,
			data->Length,
			nonce->Data,
			key->Data
		);
	}
	else if (method == 3) { // SALSA20
		result = crypto_stream_salsa20_xor(
			buffer->Data,
			data->Data,
			data->Length,
			nonce->Data,
			key->Data
		);
	}
	else {
		throw ref new Platform::InvalidArgumentException("Unable to process");
	}

	if (result != 0) {
		throw ref new Platform::Exception(0, "Error processing message");
	}

	return buffer;
}

/// <returns>32 byte key</returns>
Array<unsigned char>^ Sodium::StreamEncryption::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_stream_KEYBYTES);
}

/// <returns>24 byte nonce</returns>
Array<unsigned char>^ Sodium::StreamEncryption::GenerateNonce()
{
	return Sodium::Core::GetRandomBytes(crypto_stream_NONCEBYTES);
}

/// <returns>24 byte nonce</returns>
Array<unsigned char>^ Sodium::StreamEncryption::GenerateNonceXSalsa20()
{
	return Sodium::Core::GetRandomBytes(crypto_stream_xsalsa20_NONCEBYTES);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_stream_xsalsa20_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_stream_xsalsa20_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_stream_xsalsa20_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_stream_xsalsa20_NONCEBYTES + " bytes in length");
	}

	return Sodium::StreamEncryption::ProcessInternal(message, nonce, key, 1);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::Encrypt(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::Encrypt(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		key
	);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses Xsalsa20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::Decrypt(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_stream_xsalsa20_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_stream_xsalsa20_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_stream_xsalsa20_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_stream_xsalsa20_NONCEBYTES + " bytes in length");
	}

	return Sodium::StreamEncryption::ProcessInternal(cipherText, nonce, key, 1);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses Xsalsa20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::Decrypt(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::Decrypt(
		Sodium::internal::StringToUnsignedCharArray(cipherText),
		nonce,
		key
	);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <remarks>Uses XSalsa20 streaming cipher</remarks>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::EncryptXSalsa20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::Encrypt(
		message,
		nonce,
		key
	);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <remarks>Uses XSalsa20 streaming cipher</remarks>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::EncryptXSalsa20(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::Encrypt(
		message,
		nonce,
		key
	);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses Xsalsa20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::DecryptXSalsa20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::Decrypt(
		cipherText,
		nonce,
		key
	);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses Xsalsa20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">24 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::DecryptXSalsa20(String ^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::Decrypt(
		cipherText,
		nonce,
		key
	);
}

/// <return>8 byte nonce</return>
Array<unsigned char>^ Sodium::StreamEncryption::GenerateNonceChaCha20()
{
	return Sodium::Core::GetRandomBytes(crypto_stream_chacha20_NONCEBYTES);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <remarks>Uses ChaCha20 streaming cipher</remarks>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::EncryptChaCha20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_stream_chacha20_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_stream_chacha20_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_stream_chacha20_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_stream_chacha20_NONCEBYTES + " bytes in length");
	}

	return Sodium::StreamEncryption::ProcessInternal(message, nonce, key, 2);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <remarks>Uses ChaCha20 streaming cipher</remarks>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::EncryptChaCha20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::EncryptChaCha20(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		key
	);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses ChaCha20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::DecryptChaCha20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_stream_chacha20_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_stream_chacha20_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_stream_chacha20_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_stream_chacha20_NONCEBYTES + " bytes in length");
	}

	return Sodium::StreamEncryption::ProcessInternal(cipherText, nonce, key, 2);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses ChaCha20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::DecryptChaCha20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::DecryptChaCha20(
		Sodium::internal::StringToUnsignedCharArray(cipherText),
		nonce,
		key
	);
}

/// <return>8 byte nonce</return>
Array<unsigned char>^ Sodium::StreamEncryption::GenerateNonceSalsa20()
{
	return Sodium::Core::GetRandomBytes(crypto_stream_salsa20_NONCEBYTES);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <remarks>Uses Salsa20 streaming cipher</remarks>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::EncryptSalsa20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_stream_salsa20_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_stream_salsa20_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_stream_salsa20_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_stream_salsa20_NONCEBYTES + " bytes in length");
	}

	return Sodium::StreamEncryption::ProcessInternal(message, nonce, key, 3);
}

/// <summary>Encrypts a message with a nonce and key</summary>
/// <remarks>Uses Salsa20 streaming cipher</remarks>
/// <param name="message">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>An encrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::EncryptSalsa20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::EncryptSalsa20(
		Sodium::internal::StringToUnsignedCharArray(message),
		nonce,
		key
	);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses Salsa20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::DecryptSalsa20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_stream_salsa20_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be " + crypto_stream_salsa20_KEYBYTES + " bytes in length");
	}

	if (nonce->Length != crypto_stream_salsa20_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be " + crypto_stream_salsa20_NONCEBYTES + " bytes in length");
	}

	return Sodium::StreamEncryption::ProcessInternal(cipherText, nonce, key, 3);
}

/// <summary>Dencrypts a cipherText with a nonce and key</summary>
/// <remarks>Uses Salsa20 streaming cipher</remarks>
/// <param name="cipherText">The message to encrypt</param>
/// <param name="nonce">8 byte nonce</param>
/// <param name="key">32 byte key</param>
/// <returns>The decrypted message</returns>
Array<unsigned char>^ Sodium::StreamEncryption::DecryptSalsa20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	return Sodium::StreamEncryption::DecryptSalsa20(
		Sodium::internal::StringToUnsignedCharArray(cipherText),
		nonce,
		key
	);
}