#pragma once
#include "KeyPair.h"

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class SealedPublicKeyBox sealed
	{
	public:
		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Create(const Array<unsigned char>^ message, const Array<unsigned char>^ recipientPublicKey);
		static Array<unsigned char>^ Create(String^ message, const Array<unsigned char>^ recipientPublicKey);
		static Array<unsigned char>^ Create(const Array<unsigned char>^ message, KeyPair^ recipientKeyPair);
		static Array<unsigned char>^ Create(String^ message, KeyPair^ recipientKeyPair);
		static Array<unsigned char>^ Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ recipientSecretKey, const Array<unsigned char>^ recipientPublicKey);
		static Array<unsigned char>^ Open(const Array<unsigned char>^ cipherText, KeyPair^ recipientKeyPair);
	};
}