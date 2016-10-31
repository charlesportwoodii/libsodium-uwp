#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "KDF.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <summary>HKDF extract</summary>
/// <param name="salt">The salt buffer</param>
/// <param name="ikm">The initial key provider buffer</param>
/// <param name="provider">The MacAlgorithmProvider</param>
/// <returns>HMAC buffer</returns>
IBuffer^ Sodium::KDF::extract(IBuffer^ salt, IBuffer^ ikm, MacAlgorithmProvider^ provider)
{
	return Sodium::KDF::HMAC(salt, ikm, provider);
}

/// <summary>HKDF Expand</summary>
/// <param name="prk">The Psuedo-Random key</param>
/// <param name="info">The authentication info</param>
/// <param name="l">The output length</param>
/// <param name="provider">The MacAlgorithmProvider</param>
/// <returns></returns>
IBuffer^ Sodium::KDF::expand(IBuffer^ prk, const Array<unsigned char>^ info, int l, MacAlgorithmProvider^ provider)
{
	Array<unsigned char>^ resultBlock = ref new Array<unsigned char>(0);
	Array<unsigned char>^ result = ref new Array<unsigned char>(l);
	int bytesRemaining = l;

	for (int i = 1; bytesRemaining > 0; i++) {
		Array<unsigned char>^ currentInfo = ref new Array<unsigned char>(resultBlock->Length + info->Length + 1);
		memmove(currentInfo->Data + 0, resultBlock->Data, resultBlock->Length);
		memmove(currentInfo->Data + resultBlock->Length, info->Data, info->Length);
		currentInfo[currentInfo->Length - 1] = (byte)i;

		// Copy out the byte array
		IBuffer^ messageBuff = CryptographicBuffer::CreateFromByteArray(currentInfo);
		IBuffer^ hmac = Sodium::KDF::HMAC(prk, messageBuff, provider);
		CryptographicBuffer::CopyToByteArray(hmac, &resultBlock);

		memmove(result->Data + (l - bytesRemaining), resultBlock->Data, min(resultBlock->Length, (unsigned int)bytesRemaining));
		bytesRemaining -= resultBlock->Length;
	}

	return CryptographicBuffer::CreateFromByteArray(result);
}

/// <summary>HKDF HMAC</summary>
/// <param name="key">The key</param>
/// <param name="message">The message</param>
/// <param name="provider">The MacAlgorithmProvider</param>
/// <returns>IBuffer containing the HMAC of the message</returns>
IBuffer^ Sodium::KDF::HMAC(IBuffer^ key, IBuffer^ message, MacAlgorithmProvider^ provider)
{
	CryptographicKey^ saltKey = provider->CreateKey(key);
	IBuffer^ data = CryptographicEngine::Sign(saltKey, message);

	if (data->Length < provider->MacLength) {
		throw ref new Platform::Exception(0, "Error computing digest");
	}

	return data;
}

/// <summary>RFC 2898 Password-Based Key Derivation Function 2</summary>
/// <remarks>https://tools.ietf.org/html/rfc2898</remarks>
/// <param name="algorithm">A KeyDerivationAlgorithmNames algorithm</param>
/// <param name="password">The password to stretch</param>
/// <param name="salt">A byte salt</param>
/// <param name="iterationCount">The number of iterations</param>
/// <param name="targetSize">The output length</param>
/// <returns>targetSize PBKDF2 bytes</returns>
Array<unsigned char>^ Sodium::KDF::PBKDF2(String^ algorithm, String^ password, const Array<unsigned char>^ salt, int iterationCount, int targetSize)
{
	Array<String^>^ algorithms = {
		KeyDerivationAlgorithmNames::Pbkdf2Md5,
		KeyDerivationAlgorithmNames::Pbkdf2Sha1,
		KeyDerivationAlgorithmNames::Pbkdf2Sha256,
		KeyDerivationAlgorithmNames::Pbkdf2Sha384,
		KeyDerivationAlgorithmNames::Pbkdf2Sha384,
	};

	bool inArray = false;
	for (unsigned int i = 0; i < algorithms->Length; i++) {
		if (algorithms[i] == algorithm) {
			inArray = true;
		}
	}

	if (!inArray) {
		throw ref new Platform::InvalidArgumentException("algorithm must be a `KeyDerivationAlgorithmNames` algorithm");
	}

	KeyDerivationAlgorithmProvider^ provider = KeyDerivationAlgorithmProvider::OpenAlgorithm(algorithm);
	IBuffer^ buffSecret = CryptographicBuffer::ConvertStringToBinary(password, BinaryStringEncoding::Utf8);
	IBuffer^ buffSalt = CryptographicBuffer::CreateFromByteArray(salt);
	KeyDerivationParameters^ pbkdf2Params = KeyDerivationParameters::BuildForPbkdf2(buffSalt, iterationCount);

	CryptographicKey^ keyOriginal = provider->CreateKey(buffSecret);

	IBuffer^ keyDerived = CryptographicEngine::DeriveKeyMaterial(
		keyOriginal,
		pbkdf2Params,
		targetSize
	);

	Array<unsigned char>^ hash = ref new Array<unsigned char>(keyDerived->Length);
	CryptographicBuffer::CopyToByteArray(keyDerived, &hash);

	return hash;
}

/// <summary>RFC 2898 Password-Based Key Derivation Function 2</summary>
/// <remarks>https://tools.ietf.org/html/rfc2898</remarks>
/// <param name="algorithm">A KeyDerivationAlgorithmNames algorithm</param>
/// <param name="password">The password to stretch</param>
/// <param name="salt">A string salt</param>
/// <param name="iterationCount">The number of iterations</param>
/// <param name="targetSize">The output length</param>
/// <returns>targetSize PBKDF2 bytes</returns>
Array<unsigned char>^ Sodium::KDF::PBKDF2(String^ algorithm, String^ password, String^ salt, int iterationCount, int targetSize)
{
	return Sodium::KDF::PBKDF2(
		algorithm,
		password,
		Sodium::internal::StringToUnsignedCharArray(salt),
		iterationCount,
		targetSize
	);
}

/// <summary>RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</summary>
/// <remarks>https://tools.ietf.org/html/rfc5869</remarks>
/// <param name="algorithm">A MacAlgorithmNames algorithm</param>
/// <param name="ikm">The initial key material</param>
/// <param name="info">Additional authentication info</param>
/// <param name="outputLength">The desired output length</param>
/// <returns>The expanded key</returns>
Array<unsigned char>^ Sodium::KDF::HKDF(String^ algorithm, const Array<unsigned char>^ ikm, const Array<unsigned char>^ salt, const Array<unsigned char>^ info, int outputLength)
{
	Array<String^>^ algorithms = {
		MacAlgorithmNames::HmacMd5,
		MacAlgorithmNames::HmacSha1,
		MacAlgorithmNames::HmacSha256,
		MacAlgorithmNames::HmacSha384,
		MacAlgorithmNames::HmacSha512
	};

	bool inArray = false;
	for (unsigned int i = 0; i < algorithms->Length; i++) {
		if (algorithms[i] == algorithm) {
			inArray = true;
		}
	}

	if (!inArray) {
		throw ref new Platform::InvalidArgumentException("algorithm must be a `MacAlgorithmNames` algorithm");
	}

	MacAlgorithmProvider^ provider = MacAlgorithmProvider::OpenAlgorithm(algorithm);
	int digestLength = (int)provider->MacLength;

	// Convert the IBuffer to a salt
	IBuffer^ s;
	if (salt->Length == 0) {
		s = CryptographicBuffer::CreateFromByteArray(ref new Array<unsigned char>(digestLength));
	} else {
		s = CryptographicBuffer::CreateFromByteArray(salt);
	}

	// If the output length is set to 0, use the algorithm length
	if (outputLength == 0) {
		outputLength = provider->MacLength;
	}

	if (outputLength < 0 || outputLength > 255 * digestLength) {
		throw ref new Platform::Exception(0, "Bad output length requested of HKDF");
	}

	IBuffer^ ikmReal = CryptographicBuffer::CreateFromByteArray(ikm);
	IBuffer^ prk = Sodium::KDF::extract(s, ikmReal, provider);

	if (prk->Length < (unsigned int)digestLength) {
		throw ref new Platform::Exception(0, "Psuedo-random key is larger then digest length. Cannot perform operation");
	}

	IBuffer^ orm = Sodium::KDF::expand(prk, info, outputLength, provider);

	Array<unsigned char>^ hkdf = ref new Array<unsigned char>(orm->Length);
	CryptographicBuffer::CopyToByteArray(orm, &hkdf);

	return hkdf;
}

/// <summary>RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</summary>
/// <remarks>https://tools.ietf.org/html/rfc5869</remarks>
/// <param name="algorithm">A MacAlgorithmNames algorithm</param>
/// <param name="ikm">The initial key material</param>
/// <param name="info">Additional authentication info</param>
/// <param name="outputLength">The desired output length</param>
/// <returns>The expanded key</returns>
Array<unsigned char>^ Sodium::KDF::HKDF(String^ algorithm, const Array<unsigned char>^ ikm, const Array<unsigned char>^ salt, String^ info, int outputLength)
{
	return Sodium::KDF::HKDF(
		algorithm,
		ikm,
		salt,
		Sodium::internal::StringToUnsignedCharArray(info),
		outputLength
	);
}

/// <summary>crypto_core_hsalsa20 intermediate key</summary>
/// <param name="in">Input data</param>
/// <param name="k">The key</param>
/// <param name="c"></param>
/// <returns>crypto_core_hsalsa20 intermediate key</returns>
Array<unsigned char>^ Sodium::KDF::HSalsa20(const Array<unsigned char>^ in, const Array<unsigned char>^ k, const Array<unsigned char>^ c)
{
	if (k->Length != crypto_core_hsalsa20_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("k must be " + crypto_core_hsalsa20_KEYBYTES + " bytes in length");
	}

	Array<unsigned char>^ out = ref new Array<unsigned char>(crypto_core_hsalsa20_OUTPUTBYTES);
	int result = crypto_core_hsalsa20(
		out->Data,
		in->Data,
		k->Data,
		c->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Unable to calculate intermediate key");
	}

	return out;
}
