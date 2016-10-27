#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "Utilities.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

Array<unsigned char>^ Sodium::Utilities::Increment(const Array<unsigned char>^ value)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(value->Length);
	memcpy(buffer->Data, value->Data, value->Length);
	sodium_increment(buffer->Data, buffer->Length);

	return buffer;
}

// Constant time string comparison
bool Sodium::Utilities::Compare(const Array<unsigned char>^ a, const Array<unsigned char>^ b)
{
	int result = sodium_compare(a->Data, b->Data, a->Length);

	return result == 0;
}