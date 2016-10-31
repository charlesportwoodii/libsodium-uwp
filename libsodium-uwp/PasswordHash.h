#pragma once
#include "pch.h";

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
		size_t memory_cost;
		size_t time_cost;
	};

	public ref class PasswordHash sealed
	{
	private:
		static int DetermineAlgorithm(String^ hash);

	public:
		static property int Argon2i
		{
			int get() { return 1; }
		};

		static property int Scrypt
		{
			int get() { return 2; }
		};

		static String^ Hash(String^ password, int algorithm, PasswordHashOptions options);
		static bool Verify(String^ hash, String^ password);
	};
}