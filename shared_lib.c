#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <immintrin.h>

#ifndef LZMA_API_IMPORT
#	if !defined(LZMA_API_STATIC) && defined(_WIN32) && !defined(__GNUC__)
#		define LZMA_API_IMPORT __declspec(dllimport)
#	else
#		define LZMA_API_IMPORT
#	endif
#endif

#ifndef LZMA_API_CALL
#	if defined(_WIN32) && !defined(__CYGWIN__)
#		define LZMA_API_CALL __cdecl
#	else
#		define LZMA_API_CALL
#	endif
#endif

#ifndef LZMA_API
#	define LZMA_API(type) LZMA_API_IMPORT type LZMA_API_CALL
#endif

typedef struct {
	void *(LZMA_API_CALL *alloc)(void *opaque, size_t nmemb, size_t size);

	void (LZMA_API_CALL *free)(void *opaque, void *ptr);

	void *opaque;

} lzma_allocator;

#define no_omit_frame_pointer \
			__attribute__((optimize("no-omit-frame-pointer")))

#define lzma_resolver_attributes \
		__attribute__((__no_profile_instrument_function__)) \
		no_omit_frame_pointer

extern int _get_cpuid(int, void*, void*, void*, void*, void*);

__attribute__((always_inline))
static inline int _is_arch_extension_supported(void) { 
    int success = 1; 
    uint32_t r[4]; 
    success = _get_cpuid(1, &r[0], &r[1], &r[2], &r[3], ((char*) __builtin_frame_address(0))-16); 
    const uint32_t ecx_mask = (1 << 1) | (1 << 9) | (1 << 19); 
    return success && (r[2] & ecx_mask) == ecx_mask; 
}

typedef struct {
	/// Internal state
	uint32_t state[8];

	/// Size of the message excluding padding
	uint64_t size;
} lzma_sha256_state;

typedef struct {
	/// Buffer to hold the final result and a temporary buffer for SHA256.
	union {
		uint8_t u8[64];
		uint32_t u32[16];
		uint64_t u64[8];
	} buffer;

	/// Check-specific data
	union {
		uint32_t crc32;
		uint64_t crc64;
		lzma_sha256_state sha256;
	} state;

} lzma_check_state;

typedef enum {
	LZMA_CHECK_NONE     = 0,
		/**<
		 * No Check is calculated.
		 *
		 * Size of the Check field: 0 bytes
		 */

	LZMA_CHECK_CRC32    = 1,
		/**<
		 * CRC32 using the polynomial from the IEEE 802.3 standard
		 *
		 * Size of the Check field: 4 bytes
		 */

	LZMA_CHECK_CRC64    = 4,
		/**<
		 * CRC64 using the polynomial from the ECMA-182 standard
		 *
		 * Size of the Check field: 8 bytes
		 */

	LZMA_CHECK_SHA256   = 10
		/**<
		 * SHA-256
		 *
		 * Size of the Check field: 32 bytes
		 */
} lzma_check;


void
lzma_free(void *ptr, const lzma_allocator *allocator)
{
	if (allocator != NULL && allocator->free != NULL)
		allocator->free(allocator->opaque, ptr);
	else
		free(ptr);

	return;
}

#if defined(__GNUC__) \
		&& ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || __GNUC__ > 4)
#	define lzma_attr_alloc_size(x) __attribute__((__alloc_size__(x)))
#else
#	define lzma_attr_alloc_size(x)
#endif

lzma_attr_alloc_size(1)
void* lzma_alloc(size_t size, const lzma_allocator *allocator)
{
	// Some malloc() variants return NULL if called with size == 0.
	if (size == 0)
		size = 1;

	void *ptr;

	if (allocator != NULL && allocator->alloc != NULL)
		ptr = allocator->alloc(allocator->opaque, 1, size);
	else
		ptr = malloc(size);

	return ptr;
}

void lzma_check_init(lzma_check_state *check, lzma_check type)
{
	switch (type) {
	case LZMA_CHECK_NONE:
		break;

	case LZMA_CHECK_CRC32:
		check->state.crc32 = 0;
		break;

	case LZMA_CHECK_CRC64:
		check->state.crc64 = 0;
		break;

	case LZMA_CHECK_SHA256:
        printf("NEED MORE STUBS!");
		// lzma_sha256_init(check);
		break;
	default:
		break;
	}

	return;
}

static uint64_t
crc64_generic(const uint8_t *buf, size_t size, uint64_t crc)
{
	return 0;
}


typedef uint64_t (*crc64_func_type)(const uint8_t *buf, size_t size, uint64_t crc);

LZMA_API(uint64_t) lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc) __attribute__((__ifunc__("crc64_resolve")));

typedef uint32_t (*crc32_func_type)(
		const uint8_t *buf, size_t size, uint32_t crc);

static uint32_t
crc32_generic(const uint8_t *buf, size_t size, uint32_t crc)
{
	return 0;
}

#	define crc_attr_target \
		__attribute__((__target__("ssse3,sse4.1,pclmul")))

#	define lzma_always_inline inline __attribute__((__always_inline__))

crc_attr_target
static lzma_always_inline void
crc_simd_body(const uint8_t *buf, const size_t size, __m128i *v0, __m128i *v1,
		const __m128i vfold16, const __m128i initial_crc)
{
	return;
}

crc_attr_target
static uint32_t
crc32_arch_optimized(const uint8_t *buf, size_t size, uint32_t crc)
{
	return 0;
}

crc_attr_target
static uint64_t
crc64_arch_optimized(const uint8_t *buf, size_t size, uint64_t crc)
{
	return 0;
}

lzma_resolver_attributes
static crc32_func_type
crc32_resolve(void)
{
	return _is_arch_extension_supported()
			? &crc32_arch_optimized : &crc32_generic;
}

lzma_resolver_attributes
static crc64_func_type crc64_resolve(void)
{
	return _is_arch_extension_supported()
			? &crc64_arch_optimized : &crc64_generic;
}

LZMA_API(uint32_t) lzma_crc32(const uint8_t *buf, size_t size, uint32_t crc)
		__attribute__((__ifunc__("crc32_resolve")));

void trigger() {
	lzma_crc32(NULL,0,0);
    lzma_crc64(NULL,0,0);
}