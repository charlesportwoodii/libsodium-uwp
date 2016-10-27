#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class StreamEncryption sealed
	{
	private:
		static Array<unsigned char>^ ProcessInternal(const Array<unsigned char>^ data, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, int method);
	public:
		static Array<unsigned char>^ GenerateKey();

		static Array<unsigned char>^ GenerateNonce();

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Encrypt(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Decrypt(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Decrypt(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		static Array<unsigned char>^ GenerateNonceXSalsa20();

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ EncryptXSalsa20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ EncryptXSalsa20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ DecryptXSalsa20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptXSalsa20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		static Array<unsigned char>^ GenerateNonceChaCha20();

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ EncryptChaCha20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ EncryptChaCha20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ DecryptChaCha20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptChaCha20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		static Array<unsigned char>^ GenerateNonceSalsa20();

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ EncryptSalsa20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ EncryptSalsa20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ DecryptSalsa20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptSalsa20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
	};
}