#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// extern uint64_t lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc);
// extern uint64_t lzma_crc32(const uint8_t *buf, size_t size, uint32_t crc);
extern void trigger();

int main() {
    printf("Backdoor will now be automatically executed!\n");
    trigger();

	return 0;
}