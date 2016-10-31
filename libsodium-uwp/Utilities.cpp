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

/// <summary>Incriments a byte array (typically a nonce)</summary>
/// <param name="value">The byte array to incriment</param>
/// <returns>Incrimented byte array</returns>
Array<unsigned char>^ Sodium::Utilities::Increment(const Array<unsigned char>^ value)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(value->Length);
	memcpy(buffer->Data, value->Data, value->Length);
	sodium_increment(buffer->Data, buffer->Length);

	return buffer;
}

/// <summary>Constant time string comparison of two byte arrays</summary>
/// <returns>Boolean if two byte strings are equal</returns>
bool Sodium::Utilities::Compare(const Array<unsigned char>^ a, const Array<unsigned char>^ b)
{
	int result = sodium_compare(a->Data, b->Data, a->Length);
	return result == 0;
}

/// <summary>Constant time string comparison of string</summary>
/// <returns>Boolean if two byte strings are equal</returns>
bool Sodium::Utilities::Compare(String ^ a, String ^ b)
{
	return Sodium::Utilities::Compare(
		Sodium::internal::StringToUnsignedCharArray(a),
		Sodium::internal::StringToUnsignedCharArray(b)
	);
}
