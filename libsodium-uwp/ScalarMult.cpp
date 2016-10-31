#include "pch.h"
#include "ScalarMult.h"
#include "SodiumCore.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

int Sodium::ScalarMult::Bytes()
{
	return crypto_scalarmult_bytes();
}

int Sodium::ScalarMult::ScalarBytes()
{
	return crypto_scalarmult_scalarbytes();
}

/// <summary>Extracts the public key from the secret key</summary>
/// <param name="secretKey">The secret key</param>
/// <returns>32 byte public key</returns>
Array<unsigned char>^ Sodium::ScalarMult::Base(const Array<unsigned char>^ secretKey)
{
	if (secretKey->Length != crypto_scalarmult_SCALARBYTES) {
		throw ref new Platform::InvalidArgumentException("SecretKey must be " + crypto_scalarmult_SCALARBYTES + " bytes in length");
	}

	Array<unsigned char>^ publicKey = ref new Array<unsigned char>(crypto_scalarmult_SCALARBYTES);
	int result = crypto_scalarmult_base(
		publicKey->Data,
		secretKey->Data
	);

	if (result == 0) {
		return publicKey;
	}

	throw ref new Platform::Exception(result, "Failed to compute public key");
}

/// <summary>Computes a shared secret between a secret and public key</summary>
/// <param name="secretKey">The secret key</param>
/// <param name="publicKey">The public key</param>
/// <returns>32 byte shared secret</returns>
Array<unsigned char>^ Sodium::ScalarMult::Mult(const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_scalarmult_SCALARBYTES) {
		throw ref new Platform::InvalidArgumentException("SecretKey must be " + crypto_scalarmult_SCALARBYTES + " bytes in length");
	}

	if (publicKey->Length != crypto_scalarmult_BYTES) {
		throw ref new Platform::InvalidArgumentException("PublicKey must be " + crypto_scalarmult_BYTES + " bytes in length");
	}

	Array<unsigned char>^ sharedSecret = ref new Array<unsigned char>(crypto_scalarmult_SCALARBYTES);

	int result = crypto_scalarmult(
		sharedSecret->Data,
		secretKey->Data,
		publicKey->Data
	);

	if (result == 0) {
		return sharedSecret;
	}

	throw ref new Platform::Exception(result, "Failed to compute shared secret");
}