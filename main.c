#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

extern uint64_t lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc);
extern uint64_t lzma_crc32(const uint8_t *buf, size_t size, uint32_t crc);

int main() {
    uint8_t *buf = malloc(30);
    printf("Backdoor will now be automatically executed!\n");
    lzma_crc32(buf,30,0);
    lzma_crc64(buf,30,0);

	return 0;
}