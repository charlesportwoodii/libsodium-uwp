
#include <stdlib.h>
#include <sys/types.h>
#ifndef _WIN32
# include <sys/stat.h>
# include <sys/time.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
# include <unistd.h>
#endif

#include "randombytes.h"
#include "randombytes_uwp.h"
#include "utils.h"

#ifndef SSIZE_MAX
# define SSIZE_MAX (SIZE_MAX / 2 - 1)
#endif


typedef struct uwp_ {
    int random_data_source_fd;
    int initialized;
    int getrandom_available;
} uwp;

static uwp stream = {
    SODIUM_C99(.random_data_source_fd =) -1,
    SODIUM_C99(.initialized =) 0,
    SODIUM_C99(.getrandom_available =) 0
};

static void
randombytes_uwp_init(void)
{
}

static void
randombytes_uwp_stir(void)
{
    if (stream.initialized == 0) {
        randombytes_uwp_init();
        stream.initialized = 1;
    }
}

static void
randombytes_uwp_stir_if_needed(void)
{
    if (stream.initialized == 0) {
        randombytes_uwp_stir();
    }
}

static int
randombytes_uwp_close(void)
{
    int ret = -1;

	if (stream.initialized != 0) {
        stream.initialized = 0;
        ret = 0;
    }

    return ret;
}

static void
randombytes_uwp_buf(void * const buf, const size_t size)
{
    randombytes_uwp_stir_if_needed();
    if (size > (size_t) 0xffffffff) {
        abort(); /* LCOV_EXCL_LINE */
    }
	if (!GenerateRandomBytes((unsigned char*)buf, (unsigned int)size)) {
        abort(); /* LCOV_EXCL_LINE */
    }
}

static uint32_t
randombytes_uwp(void)
{
    uint32_t r;

    randombytes_uwp_buf(&r, sizeof r);

    return r;
}

static const char *
randombytes_uwp_implementation_name(void)
{
    return "uwp";
}

struct randombytes_implementation randombytes_uwp_implementation = {
    SODIUM_C99(.implementation_name =) randombytes_uwp_implementation_name,
    SODIUM_C99(.random =) randombytes_uwp,
    SODIUM_C99(.stir =) randombytes_uwp_stir,
    SODIUM_C99(.uniform =) NULL,
    SODIUM_C99(.buf =) randombytes_uwp_buf,
    SODIUM_C99(.close =) randombytes_uwp_close
};
