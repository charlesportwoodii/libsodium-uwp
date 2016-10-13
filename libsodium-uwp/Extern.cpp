#include "pch.h"
#include "Extern.h"

using namespace Platform;
using namespace Windows::Security::Cryptography;
using namespace Windows::Storage::Streams;

extern "C" bool GenerateRandomBytes(unsigned char *bytes, unsigned int length)
{
	IBuffer^ buffer = CryptographicBuffer::GenerateRandom(length);
	DataReader^ reader = DataReader::FromBuffer(buffer);
	reader->ReadBytes(ArrayReference<unsigned char>(bytes, buffer->Length));

	return true;
}