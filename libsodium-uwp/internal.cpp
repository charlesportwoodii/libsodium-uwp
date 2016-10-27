#include "pch.h"
#include "internal.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

// Internal helper method to convert String^ to Array<unsigned char>^
Array<unsigned char>^ Sodium::internal::StringToUnsignedCharArray(String^ str)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(str, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);

	return msg;
}