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

/// <summary>Internal function to convert a integer tag to a unsigned char</summary>
/// <param name="tag">And integer ID that corresponds to Sodium::SecretStream::TAG_*</param>
/// <returns>Returns a char array for internal use</returns>
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

/// <summary>Encrypts a given message</summary>
/// <param name="message">The message to encrypt</param>
/// <returns>An encrypted cipher text</returns>
Array<unsigned char>^ Sodium::SecretStream::Push(const Array<unsigned char>^ message)
{
	return Sodium::SecretStream::Push(
		message,
		Sodium::SecretStream::TAG_MESSAGE
	);
}

/// <summary>Encrypts a given message</summary>
/// <param name="message">The message to encrypt</param>
/// <returns>An encrypted cipher text</returns>
Array<unsigned char>^ Sodium::SecretStream::Push(String^ message)
{
	return Sodium::SecretStream::Push(
		Sodium::internal::StringToUnsignedCharArray(message),
		Sodium::SecretStream::TAG_MESSAGE
	);
}

/// <summary>Encrypts a given message</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="tag">Encrypt a message with a given tag</param>
/// <returns>An encrypted cipher text</returns>
Array<unsigned char>^ Sodium::SecretStream::Push(const Array<unsigned char>^ message, int tag)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(0);
	return Sodium::SecretStream::Push(
		message,
		tag,
		ad
	);
}

/// <summary>Encrypts a given message</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="tag">Encrypt a message with a given tag</param>
/// <returns>An encrypted cipher text</returns>
Array<unsigned char>^ Sodium::SecretStream::Push(String^ message, int tag)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(0);
	return Sodium::SecretStream::Push(
		Sodium::internal::StringToUnsignedCharArray(message),
		tag,
		ad
	);
}

/// <summary>Encrypts a given message</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="tag">Encrypt a message with a given tag</param>
/// <param name="additionalData">Additional parameters to encrypt with the stream</param>
/// <returns>An encrypted cipher text</returns>
Array<unsigned char>^ Sodium::SecretStream::Push(String^ message, int tag, String^ additionalData)
{
	return Sodium::SecretStream::Push(
		Sodium::internal::StringToUnsignedCharArray(message),
		tag,
		Sodium::internal::StringToUnsignedCharArray(additionalData)
	);
}

/// <summary>Encrypts a given message</summary>
/// <param name="message">The message to encrypt</param>
/// <param name="tag">Encrypt a message with a given tag</param>
/// <param name="additionalData">Additional parameters to encrypt with the stream</param>
/// <returns>An encrypted cipher text</returns>
Array<unsigned char>^ Sodium::SecretStream::Push(const Array<unsigned char>^ message, int tag, const Array<unsigned char>^ additionalData)
{
	if (message->Length > crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX) {
		throw ref new Platform::InvalidArgumentException("Individual messages must be less than " + crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX + " bytes in length");
	}

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

/// <summary>Decrypts a given ciphertext</summary>
/// <param name="message">The message to decrypt</param>
/// <returns>An decrypted message</returns>
Array<unsigned char>^ Sodium::SecretStream::Pull(const Array<unsigned char>^ ciphertext)
{
	return Sodium::SecretStream::Pull(
		ciphertext,
		Sodium::SecretStream::TAG_MESSAGE
	);
}

/// <summary>Decrypts a given ciphertext</summary>
/// <param name="message">The message to decrypt</param>
/// <param name="tag">Decrypts a message with a given tag</param>
/// <returns>An decrypted message</returns>
Array<unsigned char>^ Sodium::SecretStream::Pull(const Array<unsigned char>^ ciphertext, int tag)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(0);
	return Sodium::SecretStream::Pull(
		ciphertext,
		tag,
		ad
	);
}

/// <summary>Decrypts a given ciphertext</summary>
/// <param name="message">The message to decrypt</param>
/// <param name="tag">Decrypts a message with a given tag</param>
/// <param name="additionalData">Additional parameters to decrypt with the stream</param>
/// <returns>An decrypted message</returns>
Array<unsigned char>^ Sodium::SecretStream::Pull(const Array<unsigned char>^ ciphertext, int tag, String^ additionalData)
{
	return Sodium::SecretStream::Pull(
		ciphertext,
		tag,
		Sodium::internal::StringToUnsignedCharArray(additionalData)
	);
}

/// <summary>Decrypts a given ciphertext</summary>
/// <param name="message">The message to decrypt</param>
/// <param name="tag">Decrypts a message with a given tag</param>
/// <param name="additionalData">Additional parameters to decrypt with the stream</param>
/// <returns>An decrypted message</returns>
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

/// <summary>Creates a 32 byte key</summary>
/// <returns>32 byte key</returns>
Array<unsigned char>^ Sodium::SecretStream::GenerateKey()
{
	Array<unsigned char>^ key = ref new Array<unsigned char>(crypto_secretstream_xchacha20poly1305_KEYBYTES);
	crypto_secretstream_xchacha20poly1305_keygen(key->Data);

	return key;
}

/// <summary>Creates a 24 byte header</summary>
/// <returns>24 byte key</returns>
Array<unsigned char>^ Sodium::SecretStream::GenerateHeader()
{
	Array<unsigned char>^ header = ref new Array<unsigned char>(crypto_secretstream_xchacha20poly1305_HEADERBYTES);
	return header;
}

/// <summary>Explicitly forces a rekey to occur</summary>
void Sodium::SecretStream::Rekey()
{
	// Recreate the state as a crypto_secretstream_xchacha20poly1305_state object
	crypto_secretstream_xchacha20poly1305_state state;
	memcpy(&state, this->state->Data, this->state_len);

	// Trigger the rekey
	crypto_secretstream_xchacha20poly1305_rekey(&state);

	// Copy the state back onto the class
	int state_len = sizeof(state);
	
	Array<unsigned char>^ s = ref new Array<unsigned char>(state_len);
	memcpy(s->Data, &state, state_len);

	this->state = s;
	this->state_len = state_len;

	// Zero the local state
	sodium_memzero(&state, sizeof state);
}