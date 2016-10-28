#include "pch.h"
#include "SodiumCore.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

// Returns the libsodium version string
String^ Sodium::Core::SodiumVersionString()
{
	return SODIUM_VERSION_STRING;
}

// Returns count number of random bytes
Array<unsigned char>^ Sodium::Core::GetRandomBytes(int count)
{
	if (count <= 0) {
		throw ref new Platform::InvalidArgumentException("count must be greater than 0");
	}

	Array<unsigned char>^ nonce = ref new Array<unsigned char>(count);
	randombytes_buf(nonce->Data, nonce->Length);
	return nonce;
}

// Returns a random number with an upper bound of upper_count
int Sodium::Core::GetRandomNumber(int upper_count)
{
	return randombytes_uniform(upper_count);
}