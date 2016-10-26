#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class KeyPair sealed
	{
	public:
		KeyPair(const Array<unsigned char>^ Public, const Array<unsigned char>^ Secret)
		{
			this->Public = Public;
			this->Secret = Secret;
		};
		KeyPair() {};
		property Array<unsigned char>^ Public;
		property Array<unsigned char>^ Secret;
	};

	public ref class DetachedBox sealed
	{
	public:
		DetachedBox(const Array<unsigned char>^ Cipher, const Array<unsigned char>^ Mac)
		{
			this->Cipher = Cipher;
			this->Mac = Mac;
		};
		property Array<unsigned char>^ Cipher;
		property Array<unsigned char>^ Mac;
	};

	public ref class Core sealed
	{
	public:
		static String^ SodiumVersionString();
		static Array<unsigned char>^ GetRandomBytes(int count);
		static int GetRandomNumber(int upper_count);
	};

	public ref class Utilities sealed
	{
	public:
		static Array<unsigned char>^ Increment(const Array<unsigned char>^ value);
		static bool Compare(const Array<unsigned char>^ a, const Array<unsigned char>^ b);
	};

	public ref class SecretBox sealed
	{
	public:
		static Array<unsigned char>^ GenerateNonce();
		static Array<unsigned char>^ GenerateKey();
		static Array<unsigned char>^ Create(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Create(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Open(const Array<unsigned char>^ ciphertext, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static DetachedBox^ CreateDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static DetachedBox^ CreateDetached(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ OpenDetached(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ OpenDetached(String^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ OpenDetached(DetachedBox^ detached, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
	};

	public ref class SecretKeyAuth sealed
	{
	public:
		static Array<unsigned char>^ GenerateKey();
		static Array<unsigned char>^ Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Sign(String^ message, const Array<unsigned char>^ key);
		static bool Verify(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static bool Verify(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static Array<unsigned char>^ SignHmacSha256(const Array<unsigned char>^ message, const Array<unsigned char>^ key);
		static Array<unsigned char>^ SignHmacSha256(String^ message, const Array<unsigned char>^ key);
		static bool VerifyHmacSha256(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static bool VerifyHmacSha256(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static Array<unsigned char>^ SignHmacSha512(const Array<unsigned char>^ message, const Array<unsigned char>^ key);
		static Array<unsigned char>^ SignHmacSha512(String^ message, const Array<unsigned char>^ key);
		static bool VerifyHmacSha512(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static bool VerifyHmacSha512(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
	};

	public ref class SecretAead sealed
	{
	public:
		static Array<unsigned char>^ GenerateNonce();
		static Array<unsigned char>^ Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Encrypt(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData);
		static Array<unsigned char>^ Encrypt(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData);
		static Array<unsigned char>^ Decrypt(const Array<unsigned char>^ encrypted, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Decrypt(const Array<unsigned char>^ encrypted, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, const Array<unsigned char>^ additionalData);
	};

	public ref class SealedPublicKeyBox sealed
	{
	public:
		static Array<unsigned char>^ Create(const Array<unsigned char>^ message, const Array<unsigned char>^ recipientPublicKey);
		static Array<unsigned char>^ Create(String^ message, const Array<unsigned char>^ recipientPublicKey);
		static Array<unsigned char>^ Create(const Array<unsigned char>^ message, KeyPair^ recipientKeyPair);
		static Array<unsigned char>^ Create(String^ message, KeyPair^ recipientKeyPair);
		static Array<unsigned char>^ Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ recipientSecretKey, const Array<unsigned char>^ recipientPublicKey);
		static Array<unsigned char>^ Open(const Array<unsigned char>^ cipherText, KeyPair^ recipientKeyPair);
	};

	public ref class PublicKeyBox sealed
	{
	public:
		static Array<unsigned char>^ GenerateNonce();
		static KeyPair^ GenerateKeyPair();
		static KeyPair^ GenerateKeyPair(const Array<unsigned char>^ privateKey);
		static Array<unsigned char>^ Create(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ Create(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
		static DetachedBox^ CreateDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
		static DetachedBox^ CreateDetached(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ OpenDetached(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ OpenDetached(String^ cipherText, const Array<unsigned char>^ mac, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ OpenDetached(DetachedBox^ detached, const Array<unsigned char>^ nonce, const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
	};

	public ref class PublicKeyAuth sealed
	{
	public:
		static KeyPair^ GenerateKeyPair();
		static KeyPair^ GenerateKeyPair(const Array<unsigned char>^ seed);
		static Array<unsigned char>^ Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ privateKey);
		static Array<unsigned char>^ Sign(String^ message, const Array<unsigned char>^ privateKey);
		static Array<unsigned char>^ Verify(const Array<unsigned char>^ signedMessage, const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ ConvertEd25519PublicKeyToCurve25519PublicKey(const Array<unsigned char>^ publicKey);
		static Array<unsigned char>^ ConvertEd25519SecretKeyToCurve25519SecretKey(const Array<unsigned char>^ privateKey);
		static Array<unsigned char>^ SignDetached(const Array<unsigned char>^ message, const Array<unsigned char>^ secretKey);
		static Array<unsigned char>^ SignDetached(String^ message, const Array<unsigned char>^ secretKey);
		static bool VerifyDetached(const Array<unsigned char>^ signature, const Array<unsigned char>^ message, const Array<unsigned char>^ publicKey);
		static bool VerifyDetached(const Array<unsigned char>^ signature, String^ message, const Array<unsigned char>^ publicKey); 
		static Array<unsigned char>^ ExtractEd25519SeedFromEd25519SecretKey(const Array<unsigned char>^ ed25519SecretKey);
		static Array<unsigned char>^ ExtractEd25519PublicKeyFromEd25519SecretKey(const Array<unsigned char>^ ed25519SecretKey);
	};

	public ref class CryptoHash sealed
	{
	public:
		static Array<unsigned char>^ Sha256(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Sha256(String^ message);
		static Array<unsigned char>^ Sha512(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Sha512(String^ message);
		static Array<unsigned char>^ Hash(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Hash(String^ message);
	};

	public ref class ScalarMult sealed
	{
	public:
		static int Bytes();
		static int ScalarBytes();
		static Array<unsigned char>^ Base(const Array<unsigned char>^ secretKey);
		static Array<unsigned char>^ Mult(const Array<unsigned char>^ secretKey, const Array<unsigned char>^ publicKey);
	};

	public ref class KDF sealed
	{
	private:
		static IBuffer^ extract(IBuffer^ salt, IBuffer^ ikm, MacAlgorithmProvider^ provider);
		static IBuffer^ expand(IBuffer^ prk, const Array<unsigned char>^ info, int l, MacAlgorithmProvider^ provider);
		static IBuffer^ HMAC(IBuffer^ key, IBuffer^ message, MacAlgorithmProvider^ provider);
	public:
		static Array<unsigned char>^ PBKDF2(String^ algorithm, String^ password, const Array<unsigned char>^ salt, int iterationCount, int targetSize);
		static Array<unsigned char>^ PBKDF2(String^ algorithm, String^ password, String^ salt, int iterationCount, int targetSize);
		static Array<unsigned char>^ HKDF(String^ algorithm, const Array<unsigned char>^ ikm, const Array<unsigned char>^ salt, const Array<unsigned char>^ info, int outputLength);
		static Array<unsigned char>^ HKDF(String^ algorithm, const Array<unsigned char>^ ikm, const Array<unsigned char>^ salt, String^ info, int outputLength);
		static Array<unsigned char>^ HSalsa20(const Array<unsigned char>^ in, const Array<unsigned char>^ k, const Array<unsigned char>^ c);
	};

	public ref class OneTimeAuth sealed
	{
	public:
		static Array<unsigned char>^ GenerateKey();
		static Array<unsigned char>^ Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Sign(String^ message, const Array<unsigned char>^ key);
		static bool Verify(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static bool Verify(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
	};

	public ref class StreamEncryption sealed
	{
	private:
		static Array<unsigned char>^ ProcessInternal(const Array<unsigned char>^ data, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key, int method);
		
	public:
		static Array<unsigned char>^ GenerateKey();
		static Array<unsigned char>^ GenerateNonce();
		static Array<unsigned char>^ GenerateNonceXSalsa20();
		static Array<unsigned char>^ Encrypt(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Encrypt(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Decrypt(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Decrypt(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		static Array<unsigned char>^ EncryptXSalsa20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ EncryptXSalsa20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptXSalsa20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptXSalsa20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		static Array<unsigned char>^ GenerateNonceChaCha20();
		static Array<unsigned char>^ EncryptChaCha20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ EncryptChaCha20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptChaCha20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptChaCha20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);

		static Array<unsigned char>^ GenerateNonceSalsa20();
		static Array<unsigned char>^ EncryptSalsa20(const Array<unsigned char>^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ EncryptSalsa20(String^ message, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptSalsa20(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
		static Array<unsigned char>^ DecryptSalsa20(String^ cipherText, const Array<unsigned char>^ nonce, const Array<unsigned char>^ key);
	};

	private ref class internal sealed
	{
	public:
		static Array<unsigned char>^ StringToUnsignedCharArray(String^ str);
	};
}