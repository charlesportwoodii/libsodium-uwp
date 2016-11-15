#pragma once
#include "DetachedBox.h"

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class SecretBox sealed
	{
	public:
		static Array<unsigned char>^ GenerateNonce();
		static Array<unsigned char>^ GenerateKey();

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Create(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Create(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Open(const Array<unsigned char>^ ciphertext, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static DetachedBox^ CreateDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static DetachedBox^ CreateDetached(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ OpenDetached(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ OpenDetached(String^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ OpenDetached(DetachedBox^ detached, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
	};
}
