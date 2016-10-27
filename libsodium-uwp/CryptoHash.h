#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class CryptoHash sealed
	{
	public:
		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Sha256(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Sha256(String^ message);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Sha512(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Sha512(String^ message);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Hash(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Hash(String^ message);
	};
}