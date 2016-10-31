#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class Utilities sealed
	{
	public:
		static Array<unsigned char>^ Increment(const Array<unsigned char>^ value);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static bool Compare(const Array<unsigned char>^ a, const Array<unsigned char>^ b);
		static bool Compare(String^ a, String^ b);
	};
}