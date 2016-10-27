#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class ScalarMult sealed
	{
	public:
		static int Bytes();
		static int ScalarBytes();
		static Array<unsigned char>^ Base(const Array<unsigned char>^ secretKey);
		static Array<unsigned char>^ Mult(const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
	};
}