#include "pch.h"
#include "Sodium.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Storage::Streams;

// Returns the libsodium version string
String^ Sodium::Core::SodiumVersionString()
{
	return SODIUM_VERSION_STRING;
}

// Returns count number of random bytes
Array<unsigned char>^ Sodium::Core::GetRandomBytes(int count)
{
	Array<unsigned char>^ nonce = ref new Array<unsigned char>(count);
	randombytes_buf(nonce->Data, nonce->Length);
	return nonce;
}

// Returns a random number with an upper bound of upper_count
int Sodium::Core::GetRandomNumber(int upper_count)
{
	return randombytes_uniform(upper_count);
}

// Generates a SecretBox Nonce
Array<unsigned char>^ Sodium::SecretBox::GenerateNonce()
{
	return Sodium::Core::GetRandomBytes(crypto_secretbox_NONCEBYTES);
}

// Returns a SecretBox key
Array<unsigned char>^ Sodium::SecretBox::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_secretbox_KEYBYTES);
}

Array<unsigned char>^ Sodium::SecretBox::Create(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::SecretBox::Create(msg, nonce, key);
}

// Generates an encrypted message using a key and nonce
Array<unsigned char>^ Sodium::SecretBox::Create(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_secretbox_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be {0} bytes in length");
	}

	if (nonce->Length != crypto_secretbox_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be {0} bytes in length");
	}

	int cipherLength = crypto_secretbox_MACBYTES + message->Length;
	Array<unsigned char>^ cipherText = ref new Array<unsigned char>(cipherLength);
	int result = crypto_secretbox_easy(
		cipherText->Data,
		message->Data,
		message->Length,
		nonce->Data,
		key->Data
	);

	if (result == 0) {
		return cipherText;
	}

	throw ref new Platform::Exception(result, "Unable to create SecretBox");
}

// Decrypts an encrypted string using a key and nonce
Array<unsigned char>^ Sodium::SecretBox::Open(const Array<unsigned char>^ ciphertext, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_secretbox_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be {0} bytes in length");
	}

	if (nonce->Length != crypto_secretbox_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be {0} bytes in length");
	}

	int cipherLength = ciphertext->Length - crypto_secretbox_MACBYTES;
	Array<unsigned char>^ message = ref new Array<unsigned char>(cipherLength);
	int result = crypto_secretbox_open_easy(
		message->Data,
		ciphertext->Data,
		ciphertext->Length,
		nonce->Data,
		key->Data
	);

	if (result == 0) {
		return message;
	}

	throw ref new Platform::Exception(result, "Unable to open SecretBox.");
}

// Generates a 32 byte SecretKeyAuth key
Array<unsigned char>^ Sodium::SecretKeyAuth::GenerateKey()
{
	return Sodium::Core::GetRandomBytes(crypto_auth_KEYBYTES);
}

// Creates a secret key auth signature
Array<unsigned char>^ Sodium::SecretKeyAuth::Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be {0} bytes in length");
	}

	Array<unsigned char>^ signature = ref new Array<unsigned char>(crypto_auth_KEYBYTES);
	int result = crypto_auth(
		signature->Data,
		message->Data,
		message->Length,
		key->Data
	);

	if (result == 0) {
		return signature;
	}

	throw ref new Platform::Exception(result, "Unable to generate signature");
}

Array<unsigned char>^ Sodium::SecretKeyAuth::Sign(String ^ message, const Array<unsigned char>^ key)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::SecretKeyAuth::Sign(msg, key);
}

// Verifies a secret key auth signature
bool Sodium::SecretKeyAuth::Verify(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	if (key->Length != crypto_auth_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be {0} bytes in length");
	}

	if (signature->Length != crypto_auth_BYTES) {
		throw ref new Platform::InvalidArgumentException("Signature must be {0} bytes in length");
	}

	int result = crypto_auth_verify(
		signature->Data,
		message->Data,
		message->Length,
		key->Data
	);

	return result == 0;
}

bool Sodium::SecretKeyAuth::Verify(String ^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::SecretKeyAuth::Verify(msg, signature, key);
}

// Generates a SecretAEAD Nonce
Array<unsigned char>^ Sodium::SecretAead::GenerateNonce()
{
	return Sodium::Core::GetRandomBytes(crypto_aead_chacha20poly1305_NPUBBYTES);
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(1);
	ad[0] = 0x00;

	return Sodium::SecretAead::Encrypt(message, nonce, key, ad);
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::SecretAead::Encrypt(msg, nonce, key);
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData)
{
	if (key->Length != crypto_aead_chacha20poly1305_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be {0} bytes in length");
	}

	if (nonce->Length != crypto_aead_chacha20poly1305_NPUBBYTES) {
		throw ref new Platform::InvalidArgumentException("nonce must be {0} bytes in length");
	}

	if (additionalData->Length > crypto_aead_chacha20poly1305_ABYTES || additionalData->Length < 0) {
		throw ref new Platform::InvalidArgumentException("additionalData must be {0} and {1} bytes in length");
	}

	Array<unsigned char>^ cipher = ref new Array<unsigned char>(message->Length + crypto_aead_chacha20poly1305_ABYTES);
	unsigned long long cipherLength;

	int result = crypto_aead_chacha20poly1305_encrypt(
		cipher->Data,
		&cipherLength,
		message->Data,
		message->Length,
		additionalData->Data,
		additionalData->Length,
		NULL,
		nonce->Data,
		key->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(result, "Failed to encrypt message");
	}

	if (cipher->Length == cipherLength) {
		return cipher;
	}

	Array<unsigned char>^ final = ref new Array<unsigned char>(cipherLength);
	memcpy(final->Data, cipher->Data, cipherLength);
	return final;
}

Array<unsigned char>^ Sodium::SecretAead::Encrypt(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::SecretAead::Encrypt(msg, nonce, key, additionalData);
}

Array<unsigned char>^ Sodium::SecretAead::Decrypt(const Array<unsigned char>^ encrypted, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key)
{
	Array<unsigned char>^ ad = ref new Array<unsigned char>(1);
	ad[0] = 0x00;

	return Sodium::SecretAead::Decrypt(encrypted, nonce, key, ad);
}

Array<unsigned char>^ Sodium::SecretAead::Decrypt(const Array<unsigned char>^ encrypted, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData)
{
	if (key->Length != crypto_aead_chacha20poly1305_KEYBYTES) {
		throw ref new Platform::InvalidArgumentException("key must be {0} bytes in length");
	}

	if (nonce->Length != crypto_aead_chacha20poly1305_NPUBBYTES) {
		throw ref new Platform::InvalidArgumentException("nonce must be {0} bytes in length");
	}

	if (additionalData->Length > crypto_aead_chacha20poly1305_ABYTES || additionalData->Length < 0) {
		throw ref new Platform::InvalidArgumentException("additionalData must be {0} and {1} bytes in length");
	}

	Array<unsigned char>^ message = ref new Array<unsigned char>(encrypted->Length - crypto_aead_chacha20poly1305_ABYTES);
	unsigned long long messageLength;

	int result = crypto_aead_chacha20poly1305_decrypt(
		message->Data,
		&messageLength,
		NULL,
		encrypted->Data,
		encrypted->Length,
		additionalData->Data,
		additionalData->Length,
		nonce->Data,
		key->Data
	);

	if (result != 0) {
		throw ref new Platform::Exception(result, "Failed to dencrypt message");
	}

	if (message->Length == messageLength) {
		return message;
	}

	Array<unsigned char>^ final = ref new Array<unsigned char>(messageLength);
	memcpy(final->Data, message->Data, messageLength);
	return final;
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(const Array<unsigned char>^ message, const Array<unsigned char>^ recipientPublicKey)
{
	if (recipientPublicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Recipient public key must be {0} bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(message->Length + crypto_box_SEALBYTES);
	int result = crypto_box_seal(
		buffer->Data,
		message->Data,
		message->Length,
		recipientPublicKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to create SealedPublicKeyBox");
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(String ^ message, const Array<unsigned char>^ recipientPublicKey)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::SealedPublicKeyBox::Create(msg, recipientPublicKey);
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(const Array<unsigned char>^ message, KeyPair ^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(message, recipientKeyPair->Public);
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Create(String ^ message, KeyPair ^ recipientKeyPair)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::SealedPublicKeyBox::Create(msg, recipientKeyPair);
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ recipientSecretKey, const Array<unsigned char>^ recipientPublicKey)
{
	if (recipientPublicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Recipient public key must be {0} bytes in length");
	}

	if (recipientSecretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Recipient secret key must be {0} bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(cipherText->Length - crypto_box_SEALBYTES);

	int result = crypto_box_seal_open(
		buffer->Data,
		cipherText->Data,
		cipherText->Length,
		recipientPublicKey->Data,
		recipientSecretKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to open SealedPublicKeyBox");
}

Array<unsigned char>^ Sodium::SealedPublicKeyBox::Open(const Array<unsigned char>^ cipherText, KeyPair ^ recipientKeyPair)
{
	return Sodium::SealedPublicKeyBox::Create(cipherText, recipientKeyPair->Public);
}

// Generates a Crypto Box Nonce
Array<unsigned char>^ Sodium::PublicKeyBox::GenerateNonce()
{
	return Sodium::Core::GetRandomBytes(crypto_box_NONCEBYTES);
}

// Creates a PublicKey KeyPair
KeyPair^ Sodium::PublicKeyBox::GenerateKeyPair()
{
	KeyPair^ kp = ref new KeyPair();
	kp->Public = ref new Array<unsigned char>(crypto_box_PUBLICKEYBYTES);
	kp->Secret = ref new Array<unsigned char>(crypto_box_SECRETKEYBYTES);

	crypto_box_keypair(kp->Public->Data, kp->Secret->Data);

	return kp;
}

// Generates a PublicKey KeyPair from a seed
KeyPair^ Sodium::PublicKeyBox::GenerateKeyPair(const Array<unsigned char>^ privateKey)
{
	KeyPair^ kp = ref new KeyPair();
	if (privateKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must be {0} bytes");
	}

	kp->Secret = privateKey;
	kp->Public = Sodium::ScalarMult::Base(kp->Secret);

	return kp;
}

Array<unsigned char>^ Sodium::PublicKeyBox::Create(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must {0} bytes in length");
	}

	if (publicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Public key must {0} bytes in length");
	}

	if (nonce->Length != crypto_box_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be {0} bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(message->Length + crypto_box_MACBYTES);
	int result = crypto_box_easy(
		buffer->Data,
		message->Data,
		message->Length,
		nonce->Data,
		publicKey->Data,
		secretKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to create PublicKeyBox");
}

Array<unsigned char>^ Sodium::PublicKeyBox::Create(String ^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::PublicKeyBox::Create(msg, nonce, secretKey, publicKey);
}

Array<unsigned char>^ Sodium::PublicKeyBox::Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_box_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Private key must {0} bytes in length");
	}

	if (publicKey->Length != crypto_box_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Public key must {0} bytes in length");
	}

	if (nonce->Length != crypto_box_NONCEBYTES) {
		throw ref new Platform::InvalidArgumentException("Nonce must be {0} bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(cipherText->Length - crypto_box_MACBYTES);
	int result = crypto_box_open_easy(
		buffer->Data,
		cipherText->Data,
		cipherText->Length,
		nonce->Data,
		publicKey->Data,
		secretKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Unable to open PublicKeyBox");
}

// Generates a PublicKeyAuth KeyPair
KeyPair ^ Sodium::PublicKeyAuth::GenerateKeyPair()
{
	KeyPair^ kp = ref new KeyPair();
	kp->Public = ref new Array<unsigned char>(crypto_sign_PUBLICKEYBYTES);
	kp->Secret = ref new Array<unsigned char>(crypto_sign_SECRETKEYBYTES);

	crypto_sign_keypair(kp->Public->Data, kp->Secret->Data);

	return kp;
}

// Generates a PublicKeyAuth KeyPair from a seed.
KeyPair ^ Sodium::PublicKeyAuth::GenerateKeyPair(const Array<unsigned char>^ seed)
{
	KeyPair^ kp = ref new KeyPair();
	if (seed->Length != crypto_sign_SEEDBYTES) {
		throw ref new Platform::InvalidArgumentException("Seed must be {0} bytes");
	}

	kp->Public = ref new Array<unsigned char>(crypto_sign_PUBLICKEYBYTES);
	kp->Secret = ref new Array<unsigned char>(crypto_sign_SECRETKEYBYTES);
	crypto_sign_seed_keypair(kp->Public->Data, kp->Secret->Data, seed->Data);

	return kp;
}

// Signs a message given a private key
Array<unsigned char>^ Sodium::PublicKeyAuth::Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ privateKey)
{
	if (privateKey->Length != crypto_sign_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be {0} bytes in length");
	}

	unsigned long long bufferLength = 0;
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(message->Length + crypto_sign_BYTES);

	int result = crypto_sign(
		buffer->Data,
		&bufferLength,
		message->Data,
		message->Length,
		privateKey->Data
	);

	if (result == 0) {
		Array<unsigned char>^ final = ref new Array<unsigned char>(bufferLength);
		memcpy(final->Data, buffer->Data, bufferLength);
		return final;
	}

	throw ref new Platform::Exception(result, "Failed to sign message");
}

Array<unsigned char>^ Sodium::PublicKeyAuth::Sign(String ^ message, const Array<unsigned char>^ privateKey)
{
	BinaryStringEncoding encoding = BinaryStringEncoding::Utf8;
	IBuffer^ buffer = CryptographicBuffer::ConvertStringToBinary(message, encoding);
	Array<unsigned char>^ msg = ref new Array<unsigned char>(buffer->Length);
	CryptographicBuffer::CopyToByteArray(buffer, &msg);
	return Sodium::PublicKeyAuth::Sign(msg, privateKey);
}

// Verifies a signature with a public key
Array<unsigned char>^ Sodium::PublicKeyAuth::Verify(const Array<unsigned char>^ signedMessage, const Array<unsigned char>^ publicKey)
{
	if (publicKey->Length != crypto_sign_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Key must be {0} bytes in length");
	}

	unsigned long long bufferLength = 0;
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(signedMessage->Length);

	int result = crypto_sign_open(
		buffer->Data,
		&bufferLength,
		signedMessage->Data,
		signedMessage->Length,
		publicKey->Data
	);

	if (result == 0) {
		Array<unsigned char>^ final = ref new Array<unsigned char>(bufferLength);
		memcpy(final->Data, buffer->Data, bufferLength);
		return final;
	}

	throw ref new Platform::Exception(result, "Failed to verify signature");
}

// Converts an ED25519 Public Key to a Curve25519 Public Key
Array<unsigned char>^ Sodium::PublicKeyAuth::ConvertEd25519PublicKeyToCurve25519PublicKey(const Array<unsigned char>^ publicKey)
{
	if (publicKey->Length != crypto_sign_PUBLICKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("ed25519PublicKey must {0} bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_box_PUBLICKEYBYTES);

	int result = crypto_sign_ed25519_pk_to_curve25519(
		buffer->Data,
		publicKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to convert public key");
}

// Converts a Ed25519 Private Key to a Curve25519 Private Key
Array<unsigned char>^ Sodium::PublicKeyAuth::ConvertEd25519SecretKeyToCurve25519SecretKey(const Array<unsigned char>^ privateKey)
{
	if (privateKey->Length != crypto_sign_PUBLICKEYBYTES && privateKey->Length != crypto_sign_SECRETKEYBYTES) {
		throw ref new Platform::InvalidArgumentException("Secret key must be either {0} or {1} bytes in length");
	}

	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_box_SECRETKEYBYTES);

	int result = crypto_sign_ed25519_sk_to_curve25519(
		buffer->Data,
		privateKey->Data
	);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Failed to convert private key");
}

// Creates a Sha256 hash
Array<unsigned char>^ Sodium::CryptoHash::Sha256(const Array<unsigned char>^ message)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_hash_sha256_BYTES);
	int result = crypto_hash_sha256(buffer->Data, message->Data, message->Length);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Unable to generate Sha256 hash");
}

// Creates a Sha512 hash
Array<unsigned char>^ Sodium::CryptoHash::Sha512(const Array<unsigned char>^ message)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(crypto_hash_sha512_BYTES);
	int result = crypto_hash_sha512(buffer->Data, message->Data, message->Length);

	if (result == 0) {
		return buffer;
	}

	throw ref new Platform::Exception(result, "Unable to generate Sha512 hash");
}

int Sodium::ScalarMult::Bytes()
{
	return crypto_scalarmult_bytes();
}

int Sodium::ScalarMult::ScalarBytes()
{
	return crypto_scalarmult_scalarbytes();
}

// Extracts the public key from a secret key
Array<unsigned char>^ Sodium::ScalarMult::Base(const Array<unsigned char>^ secretKey)
{
	if (secretKey->Length != crypto_scalarmult_SCALARBYTES) {
		throw ref new Platform::InvalidArgumentException("SecretKey must be {0} bytes in length");
	}

	Array<unsigned char>^ publicKey = ref new Array<unsigned char>(crypto_scalarmult_SCALARBYTES);
	int result = crypto_scalarmult_base(
		publicKey->Data,
		secretKey->Data
	);

	if (result == 0) {
		return publicKey;
	}

	throw ref new Platform::Exception(result, "Failed to compute public key");
}

// Computes a shared secret
Array<unsigned char>^ Sodium::ScalarMult::Mult(const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey)
{
	if (secretKey->Length != crypto_scalarmult_SCALARBYTES) {
		throw ref new Platform::InvalidArgumentException("SecretKey must be {0} bytes in length");
	}

	if (publicKey->Length != crypto_scalarmult_BYTES) {
		throw ref new Platform::InvalidArgumentException("PublicKey must be {0} bytes in length");
	}

	Array<unsigned char>^ sharedSecret = ref new Array<unsigned char>(crypto_scalarmult_SCALARBYTES);

	int result = crypto_scalarmult(
		sharedSecret->Data,
		secretKey->Data,
		publicKey->Data
	);

	if (result == 0) {
		return sharedSecret;
	}

	throw ref new Platform::Exception(result, "Failed to compute shared secret");
}

Array<unsigned char>^ Sodium::Utilities::Increment(const Array<unsigned char>^ value)
{
	Array<unsigned char>^ buffer = ref new Array<unsigned char>(value->Length);
	memcpy(buffer->Data, value->Data, value->Length);
	sodium_increment(buffer->Data, buffer->Length);

	return buffer;
}

// Constant time string comparison
bool Sodium::Utilities::Compare(const Array<unsigned char>^ a, const Array<unsigned char>^ b)
{
	int result = sodium_compare(a->Data, b->Data, a->Length);

	return result == 0;
}
