#ifndef randombytes_uwp_H
#define randombytes_uwp_H

#include "export.h"
#include "randombytes.h"

#define RANDOMBYTES_DEFAULT_IMPLEMENTATION &randombytes_uwp_implementation;

#ifdef __cplusplus
extern "C" {
#endif

	SODIUM_EXPORT
		extern struct randombytes_implementation randombytes_uwp_implementation;

#ifdef __cplusplus
}
#endif

#endif