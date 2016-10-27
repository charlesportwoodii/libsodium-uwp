#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class DetachedBox sealed
	{
	public:
		DetachedBox(const Array<unsigned char>^ Cipher, const Array<unsigned char>^ Mac)
		{
			this->Cipher = Cipher;
			this->Mac = Mac;
		};
		property Array<unsigned char>^ Cipher;
		property Array<unsigned char>^ Mac;
	};
}