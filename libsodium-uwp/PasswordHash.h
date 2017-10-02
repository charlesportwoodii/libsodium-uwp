#pragma once
#include "pch.h"

using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation::Collections;

namespace Sodium
{
	public value struct PasswordHashOptions
	{
	public:
		int memory_cost;
		int time_cost;
	};

	public ref class PasswordHash sealed
	{
	private:
		static int DetermineAlgorithm(String^ hash);

		static String^ HashArgon2i(String^ password, PasswordHashOptions options, int algorithm = PasswordHash::Argon2id);
		static String^ HashScrypt(String^ password, PasswordHashOptions options);

		static bool VerifyArgon2i(String^ hash, String^ password);
		static bool VerifyScrypt(String^ hash, String^ password);

	public:
		static property int Argon2i
		{
			int get() { return crypto_pwhash_ALG_ARGON2I13; }
		};

		static property int Argon2id
		{
			int get() { return crypto_pwhash_ALG_ARGON2ID13; }
		}

		static property int Scrypt
		{
			int get() { return 5; }
		};

		static String^ Hash(String^ password, int algorithm, PasswordHashOptions options);
		static bool Verify(String^ hash, String^ password);
		static bool NeedsRehash(String^ hash, PasswordHashOptions options);
		static PasswordHashOptions CreateOptions(int memory_cost, int time_cost);
	};
}