#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class Core sealed
	{
	public:
		static String^ SodiumVersionString();
		static Array<unsigned char>^ GetRandomBytes(int count);
		static int GetRandomNumber(int upper_count);
	};
}