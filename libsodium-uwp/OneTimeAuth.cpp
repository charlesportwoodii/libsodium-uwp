#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "OneTimeAuth.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <returns>Returns a 32 byte key for One-Time Authentication</returns>
Array<unsigned char>^ Sodium::OneTimeAuth::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_onetimeauth_KEYBYTES);
}

/// <summary>Signs a message with a 32 byte key</summary>
/// <param name="message">The message to sign</param>
/// <param name="key">A 32 byte key to sign the message with</param>
/// <returns>Returns a 16 byte signature</returns>
Array<unsigned char>^ Sodium::OneTimeAuth::Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_onetimeauth_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be " + crypto_onetimeauth_KEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_onetimeauth_BYTES);
	int result = crypto_onetimeauth(
		buffer->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return buffer;
}

/// <summary>Signs a message with a 32 byte key</summary>
/// <param name="message">The message to sign</param>
/// <param name="key">A 32 byte key to sign the message with</param>
/// <returns>Returns a 16 byte signature</returns>
Array<unsigned char>^ Sodium::OneTimeAuth::Sign(String^ message, const Array<unsigned char>^ key)
{
	return Sodium::OneTimeAuth::Sign(
		Sodium::internal::StringToUnsignedCharArray(message),
		key
	);
}

/// <summary>Verifies a signature created by Sodoium.OneTimeAuth.Sign</summary>
/// <param name="message">The message to verify</param>
/// <param name=" signature">The 16 byte signature</param>
/// <param name="key">A 32 byte key to sign the message with</param>
/// <returns>Returns true of the signature is valid</returns>
bool Sodium::OneTimeAuth::Verify(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_onetimeauth_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be " + crypto_onetimeauth_KEYBYTES + " bytes in length");
	}

	if (signature->Length != crypto_onetimeauth_BYTES) {
		throw ref new Platform::InvalidArgumentException("signature must be " + crypto_onetimeauth_BYTES + " bytes in length");
	}

	int result = crypto_onetimeauth_verify(
		signature->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return result == 0;
}

/// <summary>Verifies a signature created by Sodoium.OneTimeAuth.Sign</summary>
/// <param name="message">The message to verify</param>
/// <param name=" signature">The 16 byte signature</param>
/// <param name="key">A 32 byte key to sign the message with</param>
/// <returns>Returns true of the signature is valid</returns>
bool Sodium::OneTimeAuth::Verify(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	return Sodium::OneTimeAuth::Verify(
		Sodium::internal::StringToUnsignedCharArray(message),
		signature,
		key
	);
}