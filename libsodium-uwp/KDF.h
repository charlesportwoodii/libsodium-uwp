#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class KDF sealed
	{
	private:
		static IBuffer^ extract(IBuffer^ salt, IBuffer^ ikm, MacAlgorithmProvider^ provider);
		static IBuffer^ expand(IBuffer^ prk, const Array<unsigned char>^ info, int l, MacAlgorithmProvider^ provider);
		static IBuffer^ HMAC(IBuffer^ key, IBuffer^ message, MacAlgorithmProvider^ provider);
	public:
		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ PBKDF2(String^ algorithm, String^ password, const Array<unsigned char>^ salt, int iterationCount, int targetSize);
		static Array<unsigned char>^ PBKDF2(String^ algorithm, String^ password, String^ salt, int iterationCount, int targetSize);
		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ HKDF(String^ algorithm, const Array<unsigned char>^ ikm, const Array<unsigned char>^ salt, const Array<unsigned char>^ info, int outputLength);
		static Array<unsigned char>^ HKDF(String^ algorithm, const Array<unsigned char>^ ikm, const Array<unsigned char>^ salt, String^ info, int outputLength);
		static Array<unsigned char>^ HSalsa20(const Array<unsigned char>^ in, const Array<unsigned char>^ k, const Array<unsigned char>^ c);
	};
}