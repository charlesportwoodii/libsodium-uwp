#include "pch.h"
#include "Sodium.h"

using namespace Libsodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Foundation::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Storage::Streams;

Array<unsigned char>^ Sodium::GetBoxNonce()
{
	Array<unsigned char>^ nonce = ref new Array<unsigned char>(crypto_box_NONCEBYTES);
	randombytes_buf(nonce->Data, nonce->Length);
	return nonce;
}