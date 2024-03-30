#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

extern int _get_cpuid(int, void*, void*, void*, void*, void*);
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
lzma_free(void *ptr, const void *allocator)
{
	// if (allocator != NULL && allocator->free != NULL)
	// 	allocator->free(allocator->opaque, ptr);
	// else
	free(ptr);

	return;
}


void* lzma_alloc(size_t size, const void *allocator)
{
	// Some malloc() variants return NULL if called with size == 0.
	if (size == 0)
		size = 1;

	void *ptr;

    // if (allocator != NULL && allocator->alloc != NULL)
    // 	ptr = allocator->alloc(allocator->opaque, 1, size);
    // else
    ptr = malloc(size);

	return ptr;
}

void lzma_check_init(lzma_check_state *check, lzma_check type)//
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
crc64_generic(const uint8_t *buf, size_t size, uint64_t crc) {
    return 0;
}

typedef uint64_t (*crc64_func_type)(const uint8_t *buf, size_t size, uint64_t crc);

static crc64_func_type crc64_resolve(void)
{
	return _is_arch_extension_supported()
			? &crc64_generic : &crc64_generic;
}

static uint64_t crc64_dispatch(const uint8_t *buf, size_t size, uint64_t crc);
static crc64_func_type crc64_func = &crc64_dispatch;

__attribute__((__constructor__))
static void
crc64_set_func(void)
{
	crc64_func = crc64_resolve();
	return;
}

extern uint64_t lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc) __attribute__((__ifunc__("crc64_resolve")));

static uint64_t
crc64_dispatch(const uint8_t *buf, size_t size, uint64_t crc)
{
	crc64_set_func();
	return crc64_func(buf, size, crc);
}

typedef uint32_t (*crc32_func_type)(
		const uint8_t *buf, size_t size, uint32_t crc);

static uint32_t
crc32_generic(const uint8_t *buf, size_t size, uint32_t crc) {
    return 0;
}

static crc32_func_type
crc32_resolve(void)
{
	return _is_arch_extension_supported()
			? &crc32_generic : &crc32_generic;
}

static uint32_t crc32_dispatch(const uint8_t *buf, size_t size, uint32_t crc);
static crc32_func_type crc32_func = &crc32_dispatch;

__attribute__((__constructor__))
static void
crc32_set_func(void)
{
	crc32_func = crc32_resolve();
	return;
}

static uint32_t
crc32_dispatch(const uint8_t *buf, size_t size, uint32_t crc)
{
	// When __attribute__((__ifunc__(...))) and
	// __attribute__((__constructor__)) isn't supported, set the
	// function pointer without any locking. If multiple threads run
	// the detection code in parallel, they will all end up setting
	// the pointer to the same value. This avoids the use of
	// mythread_once() on every call to lzma_crc32() but this likely
	// isn't strictly standards compliant. Let's change it if it breaks.
	crc32_set_func();
	return crc32_func(buf, size, crc);
}

uint32_t lzma_crc32(const uint8_t *buf, size_t size, uint32_t crc)
		__attribute__((__ifunc__("crc32_resolve")));

int main() {
    printf("Backdoor will now be automatically executed!\n");
    lzma_crc64(0,0,0);
    lzma_crc32(0,0,0);
    // printf("Running Once!\n");
    // lzma_crc64(0,0,0);
    // printf("Running Twice!\n");
    // lzma_crc64(0,0,0);
    // printf("Done running\n");
}