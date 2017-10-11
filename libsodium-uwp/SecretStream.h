#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class SecretStream sealed
	{
	private:
		property Array<unsigned char>^ state;
		property size_t state_len;

		int GetIndexFromTag(unsigned char tag);
		unsigned char GetTagFromIndex(int tag);

	public:
		SecretStream(const Array<unsigned char>^ key, const Array<unsigned char>^ header, int mode) {
			if (key == nullptr || key->Length == 0 || key->Length != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
				throw ref new Platform::InvalidArgumentException("Key must be " + crypto_secretstream_xchacha20poly1305_KEYBYTES + " bytes in length.");
			}

			if (header == nullptr || header->Length == 0 || header->Length != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
				throw ref new Platform::InvalidArgumentException("Header must be " + crypto_secretstream_xchacha20poly1305_HEADERBYTES + " bytes in length.");
			}

			// Create an initial state, then initialize it with the header and key
			crypto_secretstream_xchacha20poly1305_state state;
			if (mode == MODE_PUSH) {
				if (crypto_secretstream_xchacha20poly1305_init_push(&state, header->Data, key->Data) != 0) {
					throw ref new Platform::InvalidArgumentException("The header or key provided was not valid");
				}
			} else if (mode == MODE_PULL) {
				if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header->Data, key->Data) != 0) {
					throw ref new Platform::InvalidArgumentException("The header or key provided was not valid");
				}
			} else {
				throw ref new Platform::InvalidArgumentException("Mode must be either push or pull.");
			}

			int state_len = sizeof(state);

			Array<unsigned char>^ s = ref new Array<unsigned char>(state_len);
			memcpy(s->Data, &state, state_len);

			this->state = s;
			this->state_len = state_len;
		}

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		Array<unsigned char>^ Push(const Array<unsigned char>^ message);
		Array<unsigned char>^ Push(String^ message);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		Array<unsigned char>^ Push(const Array<unsigned char>^ message, int tag);
		Array<unsigned char>^ Push(String^ message, int tag);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		Array<unsigned char>^ Push(const Array<unsigned char>^ message, int tag, const Array<unsigned char>^ additionalData);
		Array<unsigned char>^ Push(String^ message, int tag, String^ additionalData);

		Array<unsigned char>^ Pull(const Array<unsigned char>^ ciphertext, int *tag);

		[Windows::Foundation::Metadata::DefaultOverloadAttribute]
		Array<unsigned char>^ Pull(const Array<unsigned char>^ ciphertext, int *tag, const Array<unsigned char>^ additionalData);
		Array<unsigned char>^ Pull(const Array<unsigned char>^ ciphertext, int *tag, String^ additionalData);

		void Rekey();
		
		static Array<unsigned char>^ GenerateKey();
		static Array<unsigned char>^ GenerateHeader();

		static property int TAG_MESSAGE
		{
			int get() { return 0; }
		};

		static property int TAG_PUSH
		{
			int get() { return 1; }
		};

		static property int TAG_REKEY
		{
			int get() { return 2; }
		};

		static property int TAG_FINAL
		{
			int get() { return 3; }
		};

		static property int MODE_PUSH
		{
			int get() { return 0; }
		};

		static property int MODE_PULL
		{
			int get() { return 1; }
		};
	};
}