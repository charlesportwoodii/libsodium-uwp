#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class OneTimeAuth sealed
	{
	public:
		static Array<unsigned char>^ GenerateKey();

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Sign(String^ message, const Array<unsigned char>^ key);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static bool Verify(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static bool Verify(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
	};
}