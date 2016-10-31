#include "pch.h"
#include "SodiumCore.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <returns>Returns the current version string of libsodium</returns>
String^ Sodium::Core::SodiumVersionString()
{
	return SODIUM_VERSION_STRING;
}

/// <param name="count">The number of bytes to randomly generate</param>
/// <returns>Returns "count" random bytes</returns>
Array<unsigned char>^ Sodium::Core::GetRandomBytes(int count)
{
	if (count <= 0) {
		throw ref new Platform::InvalidArgumentException("count must be greater than 0");
	}

	Array<unsigned char>^ nonce = ref new Array<unsigned char>(count);
	randombytes_buf(nonce->Data, nonce->Length);
	return nonce;
}

/// <param name="upper_count">The upper bound of the random number to generate</param>
/// <returns>Returns a random numbet between 0 and upper_count</returns>
int Sodium::Core::GetRandomNumber(int upper_count)
{
	return randombytes_uniform(upper_count);
}