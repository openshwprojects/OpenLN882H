#ifndef __LN_MISC_H__
#define __LN_MISC_H__
#include <stdint.h>

uint8_t  ln_char2hex(char c);
int      ln_char2hex_safe(char c, uint8_t *hex);
int      ln_str2bytes(uint8_t *bytes, const char *str);
int      ln_is_valid_mac_str(const char* mac_str);
int      ln_is_valid_mac(const char *mac);
int      ln_mac_str2hex(const uint8_t *str, uint8_t *hex);
int      ln_is_zero_mem(const void *addr, uint32_t size);
int      ln_generate_true_random_16bytes(uint8_t *buf);
uint32_t ln_generate_true_random_word(void);
int      ln_generate_random_mac(uint8_t *addr);

#endif /* __LN_MISC_H__ */

