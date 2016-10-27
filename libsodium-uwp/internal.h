#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	private ref class internal sealed
	{
	public:
		static Array<unsigned char>^ StringToUnsignedCharArray(String^ str);
	};
}