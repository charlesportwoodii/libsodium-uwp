#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class GenericHash sealed
	{
	public:
		static Array<unsigned char>^ GenerateKey();

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Hash(const Array<unsigned char>^ message, const Array<unsigned char>^ key, int bytes);
		static Array<unsigned char>^ Hash(String^ message, const Array<unsigned char>^ key, int bytes);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Hash(const Array<unsigned char>^ message, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Hash(String^ message, const Array<unsigned char>^ key);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Hash(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Hash(String^ message);
	};
}