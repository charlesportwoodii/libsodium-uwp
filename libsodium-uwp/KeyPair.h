#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class KeyPair sealed
	{
	public:
		KeyPair(const Array<unsigned char>^ Public, const Array<unsigned char>^ Secret)
		{
			this->Public = Public;
			this->Secret = Secret;
		};
		KeyPair() {};
		property Array<unsigned char>^ Public;
		property Array<unsigned char>^ Secret;
	};
}