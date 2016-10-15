#pragma once

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public ref class KeyPair sealed
	{
	public:
		property Array<unsigned char>^ Public;
		property Array<unsigned char>^ Secret;
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
	};

	public ref class SecretKeyAuth sealed
	{
	public:
		static Array<unsigned char>^ GenerateKey();
		static Array<unsigned char>^ Sign(const Array<unsigned char>^ message, const Array<unsigned char>^ key);
		static Array<unsigned char>^ Sign(String^ message, const Array<unsigned char>^ key);
		static bool Verify(const Array<unsigned char>^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
		static bool Verify(String^ message, const Array<unsigned char>^ signature, const Array<unsigned char>^ key);
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
		static Array<unsigned char>^ Open(const Array<unsigned char>^ cipherText, const Array<unsigned char>^ recipientSecretKey, const Array<unsigned char>^recipientPublicKey);
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
	};

	public ref class CryptoHash sealed
	{
	public:
		static Array<unsigned char>^ Sha256(const Array<unsigned char>^ message);
		static Array<unsigned char>^ Sha512(const Array<unsigned char>^ message);
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
	public:
		static Array<unsigned char>^ PBKDF2(String^ password, const Array<unsigned char>^ salt, int iterationCount, int targetSize, String^ algorithm);
	};

	private ref class internal sealed
	{
	public:
		static Array<unsigned char>^ StringToUnsignedCharArray(String^ str);
	};
}