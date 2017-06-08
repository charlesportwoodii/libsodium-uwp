#include "pch.h"
#include "SodiumCore.h"
#include "PasswordHash.h"
#include "internal.h"

using namespace Sodium;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

/// <summary>Generates a hash of the given password using the selected algorithn and options</summary>
/// <param name="password">The password to hash</param>
/// <param name="algorithm">The PasswordHash algorithm to use</param>
/// <param name="options">PasswordHashOptions struct</param>
/// <returns>The hash string</returns>
String^ Sodium::PasswordHash::Hash(String^ password, int algorithm, PasswordHashOptions options)
{
	if (password->Length() == 0) {
		throw ref new Platform::InvalidArgumentException("Password must not be null");
	}

	if (algorithm == PasswordHash::Argon2i) {
		return PasswordHash::HashArgon2i(password, options);
	} else if (algorithm == PasswordHash::Scrypt) {
		return PasswordHash::HashScrypt(password, options);
	} else {
		throw ref new Platform::InvalidArgumentException("Algorithm must be defined");
	}
}

/// <summary>Compares a given hash against a plaintext password</summary>
/// <param name="hash">The hash to check</param>
/// <param name="password">The password to check</param>
/// <returns>True of the provided password matches the string</returns>
bool Sodium::PasswordHash::Verify(String^ hash, String^ password)
{
	int algorithm = PasswordHash::DetermineAlgorithm(hash);
	
	if (algorithm == PasswordHash::Argon2i) {
		return PasswordHash::VerifyArgon2i(hash, password);
	} else if (algorithm == PasswordHash::Scrypt) {
		return PasswordHash::VerifyScrypt(hash, password);
	} else {
		throw ref new Platform::InvalidArgumentException("Hash does not match a known algorithm type");
	}
}

/// <summary>Determines the algorithm used for the selected hash</summary>
/// <param name="hash">The hash</param>
/// <returns>Integer representing the PasswordHash algorithm</returns>
int Sodium::PasswordHash::DetermineAlgorithm(String^ hash)
{
	std::string sHash(hash->Begin(), hash->End());
	size_t len = sizeof(sHash);

	if (len >= sizeof("$argon2i$") - 1 && !memcmp(sHash.c_str(), "$argon2i$", sizeof("$argon2i$") - 1)) {
		return PasswordHash::Argon2i;
	} else if (len >= sizeof("$7") - 1 && !memcmp(sHash.c_str(), "$7", sizeof("$7") - 1)) {
		return PasswordHash::Scrypt;
	} else {
		return -1;
	}
}

/// <summary>Internal method to has an Argon2i password</summary>
/// <param name="password">The password to hash</param>
/// <param name="algorithm">The PasswordHash algorithm to use</param>
/// <param name="options">PasswordHashOptions struct</param>
/// <returns>The hash string</returns>
String^ Sodium::PasswordHash::HashArgon2i(String^ password, PasswordHashOptions options)
{
	const Array<unsigned char>^ sPassword = Sodium::internal::StringToUnsignedCharArray(password);

	sodium_mlock(sPassword->Data, sPassword->Length);

	if (options.memory_cost <= 0) {
		throw ref new Platform::InvalidArgumentException("options.memory_cost must be greater than 0");
	}

	if (options.time_cost < 3) {
		throw ref new Platform::InvalidArgumentException("options.time_cost must be greater than 3");
	}

	char hash[crypto_pwhash_STRBYTES];

	int result = crypto_pwhash_str(
		hash,
		(const char*)sPassword->Data,
		sPassword->Length,
		options.time_cost,
		(options.memory_cost * 1024U)
	);

	sodium_munlock(sPassword->Data, sPassword->Length);
	sodium_memzero(sPassword->Data, sPassword->Length);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Out of memory");
	}

	std::string hash_str = std::string(hash);
	std::wstring whash_str = std::wstring(hash_str.begin(), hash_str.end());
	return ref new Platform::String(whash_str.c_str());
}

/// <summary>Internal method to hash an Scrypt password</summary>
/// <param name="password">The password to hash</param>
/// <param name="algorithm">The PasswordHash algorithm to use</param>
/// <param name="options">PasswordHashOptions struct</param>
/// <returns>The hash string</returns>
String^ Sodium::PasswordHash::HashScrypt(String^ password, PasswordHashOptions options)
{
	const Array<unsigned char>^ sPassword = Sodium::internal::StringToUnsignedCharArray(password);

	sodium_mlock(sPassword->Data, sPassword->Length);

	if (options.memory_cost <= 0) {
		throw ref new Platform::InvalidArgumentException("options.memory_cost must be greater than 0");
	}

	if (options.time_cost <= 0) {
		throw ref new Platform::InvalidArgumentException("options.time_cost must be greater than 0");
	}

	char hash[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
	int result = crypto_pwhash_scryptsalsa208sha256_str(
		hash,
		(const char*)sPassword->Data,
		sPassword->Length,
		options.time_cost,
		(options.memory_cost * 1024U)
	);

	sodium_munlock(sPassword->Data, sPassword->Length);
	sodium_memzero(sPassword->Data, sPassword->Length);

	if (result != 0) {
		throw ref new Platform::Exception(0, "Out of memory");
	}

	std::string hash_str = std::string(hash);
	std::wstring whash_str = std::wstring(hash_str.begin(), hash_str.end());
	return ref new Platform::String(whash_str.c_str());
}

/// <summary>Internal method to verify an Argon2i password</summary>
/// <param name="hash">The hash to check</param>
/// <param name="password">The password to check</param>
/// <returns>True of the provided password matches the string</returns>
bool Sodium::PasswordHash::VerifyArgon2i(String^ hash, String ^ password)
{
	std::string sHash(hash->Begin(), hash->End());
	std::string sPassword(password->Begin(), password->End());

	sodium_mlock((void*)sPassword.c_str(), strlen(sPassword.c_str()));

	int result = crypto_pwhash_str_verify(
		sHash.c_str(),
		sPassword.c_str(),
		strlen(sPassword.c_str())
	);

	sodium_munlock((void*)sPassword.c_str(), strlen(sPassword.c_str()));
	sodium_memzero((void*)sPassword.c_str(), strlen(sPassword.c_str()));

	return result == 0;
}

/// <summary>Internal method to verify an Scrypt password</summary>
/// <param name="hash">The hash to check</param>
/// <param name="password">The password to check</param>
/// <returns>True of the provided password matches the string</returns>
bool Sodium::PasswordHash::VerifyScrypt(String^ hash, String ^ password)
{
	std::string sHash(hash->Begin(), hash->End());
	std::string sPassword(password->Begin(), password->End());

	sodium_mlock((void*)sPassword.c_str(), strlen(sPassword.c_str()));

	int result = crypto_pwhash_scryptsalsa208sha256_str_verify(
		sHash.c_str(),
		sPassword.c_str(),
		strlen(sPassword.c_str())
	);

	sodium_munlock((void*)sPassword.c_str(), strlen(sPassword.c_str()));
	sodium_memzero((void*)sPassword.c_str(), strlen(sPassword.c_str()));

	return result == 0;
}

/// <summary>Creates a PasswordHashOptions struct</summary>
/// <param name="memory_cost">The memory cost </param>
/// <param name="time_cost">The time cost </param>
/// <returns>PasswordHashOptions</returns>
PasswordHashOptions Sodium::PasswordHash::CreateOptions(int memory_cost, int time_cost)
{
	if (memory_cost <= 0) {
		throw ref new Platform::InvalidArgumentException("memory_cost must be greater than 0");
	}

	if (time_cost <= 0) {
		throw ref new Platform::InvalidArgumentException("time_cost must be greater than 0");
	}

	PasswordHashOptions options = { memory_cost, time_cost };

	return options;
}