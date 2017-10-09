#include "pch.h"
#include "SodiumCore.h"
#include "internal.h"
#include "SecretStream.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

unsigned char Sodium::SecretStream::GetTagFromIndex(int tag)
{
	if (tag == 0) {
		return crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
	} else if (tag == 1) {
		return crypto_secretstream_xchacha20poly1305_TAG_PUSH;
	} else if (tag == 2) {
		return crypto_secretstream_xchacha20poly1305_TAG_REKEY;
	} else if (tag == 3) {
		return crypto_secretstream_xchacha20poly1305_TAG_FINAL;
	}

	throw ref new Platform::InvalidArgumentException("Unable to determine tag from index");
}

Array<unsigned char>^ Sodium::SecretStream::Push(const Array<unsigned char>^ message)
{
	return Sodium::SecretStream::Push(
		message,
		Sodium::SecretStream::TAG_MESSAGE
	);
}

Array<unsigned char>^ Sodium::SecretStream::Push(String^ message)
{
	return Sodium::SecretStream::Push(
		Sodium::internal::StringToUnsignedCharArray(message),
		Sodium::SecretStream::TAG_MESSAGE
	);
}

Array<unsigned char>^ Sodium::SecretStream::Push(const Array<unsigned char>^ message, int tag)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(0);
	return Sodium::SecretStream::Push(
		message,
		tag,
		ad
	);
}

Array<unsigned char>^ Sodium::SecretStream::Push(String ^ message, int tag)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(0);
	return Sodium::SecretStream::Push(
		Sodium::internal::StringToUnsignedCharArray(message),
		tag,
		ad
	);
}

Array<unsigned char>^ Sodium::SecretStream::Push(String^ message, int tag, String^ additionalData)
{
	return Sodium::SecretStream::Push(
		Sodium::internal::StringToUnsignedCharArray(message),
		tag,
		Sodium::internal::StringToUnsignedCharArray(additionalData)
	);
}

Array<unsigned char>^ Sodium::SecretStream::Pull(const Array<unsigned char>^ ciphertext)
{
	return Sodium::SecretStream::Pull(
		ciphertext,
		Sodium::SecretStream::TAG_MESSAGE
	);
}

Array<unsigned char>^ Sodium::SecretStream::Pull(const Array<unsigned char>^ ciphertext, int tag)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(0);
	return Sodium::SecretStream::Pull(
		ciphertext,
		tag,
		ad
	);
}

Array<unsigned char>^ Sodium::SecretStream::Pull(const Array<unsigned char>^ ciphertext, int tag, String^ additionalData)
{
	return Sodium::SecretStream::Pull(
		ciphertext,
		tag,
		Sodium::internal::StringToUnsignedCharArray(additionalData)
	);
}

Array<unsigned char>^ Sodium::SecretStream::Push(const Array<unsigned char>^ message, int tag, const Array<unsigned char>^ additionalData)
{
	Array<unsigned char>^ ciphertext = ref new Array<unsigned char>(message->Length + crypto_secretstream_xchacha20poly1305_ABYTES);

	crypto_secretstream_xchacha20poly1305_state state;
	memcpy(&state, this->state->Data, this->state_len);
	crypto_secretstream_xchacha20poly1305_push(
		&state,
		ciphertext->Data,
		NULL,
		message->Data,
		message->Length,
		additionalData->Length == 0 ? NULL : additionalData->Data,
		additionalData->Length,
		tag == 0 ? 0 : GetTagFromIndex(tag)
	);

	return ciphertext;
}

Array<unsigned char>^ Sodium::SecretStream::Pull(const Array<unsigned char>^ ciphertext, int tag, const Array<unsigned char>^ additionalData)
{
	Array<unsigned char>^ message = ref new Array<unsigned char>(ciphertext->Length - crypto_secretstream_xchacha20poly1305_ABYTES);
	unsigned char tagActual = GetTagFromIndex(tag);

	crypto_secretstream_xchacha20poly1305_state state;
	memcpy(&state, this->state->Data, this->state_len);

	int result = crypto_secretstream_xchacha20poly1305_pull(
		&state,
		message->Data,
		NULL,
		&tagActual,
		ciphertext->Data,
		ciphertext->Length,
		additionalData->Length == 0 ? NULL : additionalData->Data,
		additionalData->Length
	);

	if (result != 0) {
		throw ref new Platform::FailureException("Invalid, incomplete, or corrupted ciphertext.");
	}

	return message;
}

/// <returns>32 byte key</returns>
Array<unsigned char>^ Sodium::SecretStream::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_secretstream_xchacha20poly1305_KEYBYTES);
}

/// <returns>24 byte key</returns>
Array<unsigned char>^ Sodium::SecretStream::GenerateHeader()
{
	return Sodium::Core::GetRandomBytes(crypto_secretstream_xchacha20poly1305_HEADERBYTES);
}
