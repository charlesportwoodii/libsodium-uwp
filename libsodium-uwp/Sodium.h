#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Foundation::Collections;

namespace Libsodium
{
	public ref class Sodium sealed
	{
	public:
		Array<unsigned char>^ GetBoxNonce();
	};
}