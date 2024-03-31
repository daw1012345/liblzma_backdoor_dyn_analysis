#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <immintrin.h>
#include "tables.h"

#	define A(x) ((x) & 0xFF)
#	define B(x) (((x) >> 8) & 0xFF)
#	define C(x) (((x) >> 16) & 0xFF)
#	define D(x) ((x) >> 24)

#	define S8(x) ((x) >> 8)
#	define S32(x) ((x) >> 32)

#	define A1 A

static inline uint32_t
aligned_read32ne(const uint8_t *buf)
{
	return *(const uint32_t *)buf;
}



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
	crc = ~crc;


	if (size > 4) {
		while ((uintptr_t)(buf) & 3) {
			crc = lzma_crc64_table[0][*buf++ ^ A1(crc)] ^ S8(crc);
			--size;
		}

		const uint8_t *const limit = buf + (size & ~(size_t)(3));
		size &= (size_t)(3);

		while (buf < limit) {
#ifdef WORDS_BIGENDIAN
			const uint32_t tmp = (uint32_t)(crc >> 32)
					^ aligned_read32ne(buf);
#else
			const uint32_t tmp = (uint32_t)crc
					^ aligned_read32ne(buf);
#endif
			buf += 4;

			crc = lzma_crc64_table[3][A(tmp)]
			    ^ lzma_crc64_table[2][B(tmp)]
			    ^ S32(crc)
			    ^ lzma_crc64_table[1][C(tmp)]
			    ^ lzma_crc64_table[0][D(tmp)];
		}
	}

	while (size-- != 0)
		crc = lzma_crc64_table[0][*buf++ ^ A1(crc)] ^ S8(crc);

	return ~crc;
}


typedef uint64_t (*crc64_func_type)(const uint8_t *buf, size_t size, uint64_t crc);

extern uint64_t lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc) __attribute__((__ifunc__("crc64_resolve")));

typedef uint32_t (*crc32_func_type)(
		const uint8_t *buf, size_t size, uint32_t crc);

static uint32_t
crc32_generic(const uint8_t *buf, size_t size, uint32_t crc)
{
	crc = ~crc;

	if (size > 8) {
		// Fix the alignment, if needed. The if statement above
		// ensures that this won't read past the end of buf[].
		while ((uintptr_t)(buf) & 7) {
			crc = lzma_crc32_table[0][*buf++ ^ A(crc)] ^ S8(crc);
			--size;
		}

		// Calculate the position where to stop.
		const uint8_t *const limit = buf + (size & ~(size_t)(7));

		// Calculate how many bytes must be calculated separately
		// before returning the result.
		size &= (size_t)(7);

		// Calculate the CRC32 using the slice-by-eight algorithm.
		while (buf < limit) {
			crc ^= aligned_read32ne(buf);
			buf += 4;

			crc = lzma_crc32_table[7][A(crc)]
			    ^ lzma_crc32_table[6][B(crc)]
			    ^ lzma_crc32_table[5][C(crc)]
			    ^ lzma_crc32_table[4][D(crc)];

			const uint32_t tmp = aligned_read32ne(buf);
			buf += 4;

			// At least with some compilers, it is critical for
			// performance, that the crc variable is XORed
			// between the two table-lookup pairs.
			crc = lzma_crc32_table[3][A(tmp)]
			    ^ lzma_crc32_table[2][B(tmp)]
			    ^ crc
			    ^ lzma_crc32_table[1][C(tmp)]
			    ^ lzma_crc32_table[0][D(tmp)];
		}
	}

	while (size-- != 0)
		crc = lzma_crc32_table[0][*buf++ ^ A(crc)] ^ S8(crc);

	return ~crc;
}

#	define crc_attr_target \
		__attribute__((__target__("ssse3,sse4.1,pclmul")))

#define MASK_L(in, mask, r) r = _mm_shuffle_epi8(in, mask)

#define MASK_H(in, mask, r) \
	r = _mm_shuffle_epi8(in, _mm_xor_si128(mask, vsign))

#define MASK_LH(in, mask, low, high) \
	MASK_L(in, mask, low); \
	MASK_H(in, mask, high)


#	define lzma_always_inline inline __attribute__((__always_inline__))

crc_attr_target
static lzma_always_inline void
crc_simd_body(const uint8_t *buf, const size_t size, __m128i *v0, __m128i *v1,
		const __m128i vfold16, const __m128i initial_crc)
{
	// Create a vector with 8-bit values 0 to 15. This is used to
	// construct control masks for _mm_blendv_epi8 and _mm_shuffle_epi8.
	const __m128i vramp = _mm_setr_epi32(
			0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c);

	// This is used to inverse the control mask of _mm_shuffle_epi8
	// so that bytes that wouldn't be picked with the original mask
	// will be picked and vice versa.
	const __m128i vsign = _mm_set1_epi8(-0x80);

	// Memory addresses A to D and the distances between them:
	//
	//     A           B     C         D
	//     [skip_start][size][skip_end]
	//     [     size2      ]
	//
	// A and D are 16-byte aligned. B and C are 1-byte aligned.
	// skip_start and skip_end are 0-15 bytes. size is at least 1 byte.
	//
	// A = aligned_buf will initially point to this address.
	// B = The address pointed by the caller-supplied buf.
	// C = buf + size == aligned_buf + size2
	// D = buf + size + skip_end == aligned_buf + size2 + skip_end
	const size_t skip_start = (size_t)((uintptr_t)buf & 15);
	const size_t skip_end = (size_t)((0U - (uintptr_t)(buf + size)) & 15);
	const __m128i *aligned_buf = (const __m128i *)(
			(uintptr_t)buf & ~(uintptr_t)15);

	// If size2 <= 16 then the whole input fits into a single 16-byte
	// vector. If size2 > 16 then at least two 16-byte vectors must
	// be processed. If size2 > 16 && size <= 16 then there is only
	// one 16-byte vector's worth of input but it is unaligned in memory.
	//
	// NOTE: There is no integer overflow here if the arguments
	// are valid. If this overflowed, buf + size would too.
	const size_t size2 = skip_start + size;

	// Masks to be used with _mm_blendv_epi8 and _mm_shuffle_epi8:
	// The first skip_start or skip_end bytes in the vectors will have
	// the high bit (0x80) set. _mm_blendv_epi8 and _mm_shuffle_epi8
	// will produce zeros for these positions. (Bitwise-xor of these
	// masks with vsign will produce the opposite behavior.)
	const __m128i mask_start
			= _mm_sub_epi8(vramp, _mm_set1_epi8((char)skip_start));
	const __m128i mask_end
			= _mm_sub_epi8(vramp, _mm_set1_epi8((char)skip_end));

	// Get the first 1-16 bytes into data0. If loading less than 16
	// bytes, the bytes are loaded to the high bits of the vector and
	// the least significant positions are filled with zeros.
	const __m128i data0 = _mm_blendv_epi8(_mm_load_si128(aligned_buf),
			_mm_setzero_si128(), mask_start);
	aligned_buf++;

	__m128i v2, v3;
	{
		// There is more than 16 bytes of input.
		const __m128i data1 = _mm_load_si128(aligned_buf);
		const __m128i *end = (const __m128i*)(
				(const char *)aligned_buf - 16 + size2);
		aligned_buf++;

		MASK_LH(initial_crc, mask_start, *v0, *v1);
		*v0 = _mm_xor_si128(*v0, data0);
		*v1 = _mm_xor_si128(*v1, data1);

		while (aligned_buf < end) {
			*v1 = _mm_xor_si128(*v1, _mm_clmulepi64_si128(
					*v0, vfold16, 0x00));
			*v0 = _mm_xor_si128(*v1, _mm_clmulepi64_si128(
					*v0, vfold16, 0x11));
			*v1 = _mm_load_si128(aligned_buf++);
		}

		if (aligned_buf != end) {
			MASK_H(*v0, mask_end, v2);
			MASK_L(*v0, mask_end, *v0);
			MASK_L(*v1, mask_end, v3);
			*v1 = _mm_or_si128(v2, v3);
		}

		*v1 = _mm_xor_si128(*v1, _mm_clmulepi64_si128(
				*v0, vfold16, 0x00));
		*v0 = _mm_xor_si128(*v1, _mm_clmulepi64_si128(
				*v0, vfold16, 0x11));
		*v1 = _mm_srli_si128(*v0, 8);
	}
}

crc_attr_target
static uint32_t
crc32_arch_optimized(const uint8_t *buf, size_t size, uint32_t crc)
{

	// uint32_t poly = 0xedb88320;
	const int64_t p = 0x1db710640; // p << 1
	const int64_t mu = 0x1f7011641; // calc_lo(p, p, 32) << 1 | 1
	const int64_t k5 = 0x163cd6124; // calc_hi(p, p, 32) << 1
	const int64_t k4 = 0x0ccaa009e; // calc_hi(p, p, 64) << 1
	const int64_t k3 = 0x1751997d0; // calc_hi(p, p, 128) << 1

	const __m128i vfold4 = _mm_set_epi64x(mu, p);
	const __m128i vfold8 = _mm_set_epi64x(0, k5);
	const __m128i vfold16 = _mm_set_epi64x(k4, k3);

	__m128i v0, v1, v2;

	crc_simd_body(buf,  size, &v0, &v1, vfold16,
			_mm_cvtsi32_si128((int32_t)~crc));

	v1 = _mm_xor_si128(
			_mm_clmulepi64_si128(v0, vfold16, 0x10), v1); // xxx0
	v2 = _mm_shuffle_epi32(v1, 0xe7); // 0xx0
	v0 = _mm_slli_epi64(v1, 32);  // [0]
	v0 = _mm_clmulepi64_si128(v0, vfold8, 0x00);
	v0 = _mm_xor_si128(v0, v2);   // [1] [2]
	v2 = _mm_clmulepi64_si128(v0, vfold4, 0x10);
	v2 = _mm_clmulepi64_si128(v2, vfold4, 0x00);
	v0 = _mm_xor_si128(v0, v2);   // [2]
	return ~(uint32_t)_mm_extract_epi32(v0, 2);
}

crc_attr_target
static uint64_t
crc64_arch_optimized(const uint8_t *buf, size_t size, uint64_t crc)
{
	// const uint64_t poly = 0xc96c5795d7870f42; // CRC polynomial
	const uint64_t p  = 0x92d8af2baf0e1e85; // (poly << 1) | 1
	const uint64_t mu = 0x9c3e466c172963d5; // (calc_lo(poly) << 1) | 1
	const uint64_t k2 = 0xdabe95afc7875f40; // calc_hi(poly, 1)
	const uint64_t k1 = 0xe05dd497ca393ae4; // calc_hi(poly, k2)

	const __m128i vfold8 = _mm_set_epi64x((int64_t)p, (int64_t)mu);
	const __m128i vfold16 = _mm_set_epi64x((int64_t)k2, (int64_t)k1);

	__m128i v0, v1, v2;

	crc_simd_body(buf,  size, &v0, &v1, vfold16,
			_mm_set_epi64x(0, (int64_t)~crc));

	v1 = _mm_xor_si128(_mm_clmulepi64_si128(v0, vfold16, 0x10), v1);
	v0 = _mm_clmulepi64_si128(v1, vfold8, 0x00);
	v2 = _mm_clmulepi64_si128(v0, vfold8, 0x10);
	v0 = _mm_xor_si128(_mm_xor_si128(v1, _mm_slli_si128(v0, 8)), v2);
	return ~(((uint64_t)(uint32_t)_mm_extract_epi32(v0, 3) << 32) |
			(uint64_t)(uint32_t)_mm_extract_epi32(v0, 2));
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

uint32_t lzma_crc32(const uint8_t *buf, size_t size, uint32_t crc)
		__attribute__((__ifunc__("crc32_resolve")));

