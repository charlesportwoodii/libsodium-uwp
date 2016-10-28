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
	private:
		property int bytes;
		property Array<unsigned char>^ state;
		property size_t state_len;

	public:
		GenericHash(const Array<unsigned char>^ key, int bytes)
		{
			// Validate key length
			if (key == nullptr || key->Length == 0) {
				key = nullptr;
			} else {
				if (key->Length > crypto_generichash_KEYBYTES_MAX || key->Length < crypto_generichash_KEYBYTES_MIN) {
					throw ref new Platform::InvalidArgumentException("Key must be between " + crypto_generichash_KEYBYTES_MIN + " and " + crypto_generichash_KEYBYTES_MAX + " bytes in length");
				}
			}

			if (bytes > crypto_generichash_BYTES_MAX || bytes < crypto_generichash_BYTES_MIN) {
				throw ref new Platform::InvalidArgumentException("Bytes must be between " + crypto_generichash_BYTES_MIN + " and " + crypto_generichash_BYTES_MAX + " bytes in length");
			}

			this->bytes = bytes;

			crypto_generichash_state state;
			size_t state_len = sizeof(state);

			int result = crypto_generichash_init(
				&state,
				(key == nullptr ? NULL : key->Data),
				(key == nullptr ? 0 : key->Length),
				this->bytes
			);

			Array<unsigned char>^ s = ref new Array<unsigned char>(state_len);
			memcpy(s->Data, &state, state_len);
			
			this->state = s;
			this->state_len = state_len;
		}

		// Class methods
		void Append(IBuffer^ data);
		Array<unsigned char>^ GetValueAndReset();

		// Static methods
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

	public ref class GenericHashAlgorithmNames sealed
	{
	public:
		static property String^ Blake2
		{
			String^ get() { return "Blake2"; }
		}
	};

	public ref class GenericHashAlgorithmProvider sealed
	{
	private:
		String^ algorithm;

	public:
		GenericHashAlgorithmProvider(String^ algorithm) {
			if (algorithm != GenericHashAlgorithmNames::Blake2) {

			}
			this->algorithm = algorithm;
		}

		static GenericHashAlgorithmProvider^ OpenAlgorithm(String^ algorithm);
		GenericHash^ CreateHash();
		GenericHash^ CreateHash(const Array<unsigned char>^ key);
		GenericHash^ CreateHash(const Array<unsigned char>^ key, int bytes);
	};
}