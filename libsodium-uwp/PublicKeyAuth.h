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
	public ref class PublicKeyAuth sealed
	{
	private:
		property Array<unsigned char>^ state;
		property size_t state_len;

	public:
		PublicKeyAuth()
		{
			crypto_sign_state state;
			size_t state_len = sizeof(state);

			int result = crypto_sign_init(&state);

			Array<unsigned char>^ s = ref new Array<unsigned char>(state_len);
			memcpy(s->Data, &state, state_len);

			this->state = s;
			this->state_len = state_len;
		}

		// Class methods
		void Append(IBuffer^ data);
		Array<unsigned char>^ GetValueAndReset(const Array<unsigned char>^ secretKey);
		bool GetValueAndVerify(const Array<unsigned char>^ signature, const Array<unsigned char>^ publicKey);

		static KeyPair^ GenerateKeyPair();
		static KeyPair^ GenerateKeyPair(const Array<unsigned char>^ seed);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ privateKey);
		static Array<unsigned char>^ Sign(String^ message, const Array<unsigned char>^ privateKey);
		static Array<unsigned char>^ Verify(const Array<unsigned char>^ signedMessage, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ ConvertEd25519PublicKeyToCurve25519PublicKey(const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ ConvertEd25519SecretKeyToCurve25519SecretKey(const Array<unsigned char>^ privateKey);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static Array<unsigned char>^ SignDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ secretKey);
		static Array<unsigned char>^ SignDetached(String^ message, const Array<unsigned char>^ secretKey);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		static bool VerifyDetached(const Array<unsigned char>^ signature, const Array<unsigned char>^ message, const Array<unsigned char>^ publicKey);
		static bool VerifyDetached(const Array<unsigned char>^ signature, String^ message, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ ExtractEd25519SeedFromEd25519SecretKey(const Array<unsigned char>^ ed25519SecretKey);
		static Array<unsigned char>^ ExtractEd25519PublicKeyFromEd25519SecretKey(const Array<unsigned char>^ ed25519SecretKey);
	};
}