/*
 * fast-pbkdf2 - Optimal PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "utils/fastpbkdf2/fastpbkdf2.h"

#include <assert.h>
#include <string.h>

#if defined (__CC_ARM)
#pragma push
#pragma O3
#pragma Otime
#elif defined (__GNUC__)
#pragma GCC push_options
#pragma GCC optimize(2)
#endif

//#include <openssl/sha.h>

/* --- MSVC doesn't support C99 --- */
#ifdef _MSC_VER
#define restrict
#define _Pragma __pragma
#endif

/* --- Common useful things --- */
#define MIN(a, b) ((a) > (b)) ? (b) : (a)
#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define rotr32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define rotr64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static inline uint32_t read32_be(const uint8_t x[4])
{
#if defined(__GNUC__) && __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap32(*(uint32_t *)(x));
#else
  uint32_t r = (uint32_t)(x[0]) << 24 |
               (uint32_t)(x[1]) << 16 |
               (uint32_t)(x[2]) << 8 |
               (uint32_t)(x[3]);
  return r;
#endif
}

static inline void write32_be(uint32_t n, uint8_t out[4])
{
#if defined(__GNUC__) && __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  *(uint32_t *)(out) = __builtin_bswap32(n);
#else
  out[0] = (n >> 24) & 0xff;
  out[1] = (n >> 16) & 0xff;
  out[2] = (n >> 8) & 0xff;
  out[3] = n & 0xff;
#endif
}

static inline uint64_t read64_be(const uint8_t x[8])
{
#if defined(__GNUC__) && __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap64(*(uint64_t *)(x));
#else
  uint64_t r = (uint64_t)(x[0]) << 56 |
               (uint64_t)(x[1]) << 48 |
               (uint64_t)(x[2]) << 40 |
               (uint64_t)(x[3]) << 32 |
               (uint64_t)(x[4]) << 24 |
               (uint64_t)(x[5]) << 16 |
               (uint64_t)(x[6]) << 8 |
               (uint64_t)(x[7]);
  return r;
#endif
}

static inline void write64_be(uint64_t n, uint8_t out[8])
{
#if defined(__GNUC__) &&  __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  *(uint64_t *)(out) = __builtin_bswap64(n);
#else
  write32_be((n >> 32) & 0xffffffff, out);
  write32_be(n & 0xffffffff, out + 4);
#endif
}



/* Prepare block (of blocksz bytes) to contain md padding denoting a msg-size
 * message (in bytes).  block has a prefix of used bytes.
 *
 * Message length is expressed in 32 bits (so suitable for sha1, sha256, sha512). */
static inline void md_pad(uint8_t *block, size_t blocksz, size_t used, size_t msg)
{
  memset(block + used, 0, blocksz - used - 4);
  block[used] = 0x80;
  block += blocksz - 4;
  write32_be((uint32_t) (msg * 8), block);
}



#include <string.h>
#include <assert.h>
#include <stdint.h>
typedef void (*cf_blockwise_in_fn)(void *ctx, const uint8_t *data);

void cf_blockwise_accumulate(uint8_t *partial, size_t *npartial, size_t nblock,
                             const void *inp, size_t nbytes,
                             cf_blockwise_in_fn process,
                             void *ctx)
{
  const uint8_t *bufin = inp;
  assert(partial && *npartial < nblock);
  assert(inp || !nbytes);
  assert(process && ctx);

  /* If we have partial data, copy in to buffer. */
  if (*npartial && nbytes)
  {
    size_t space = nblock - *npartial;
    size_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    /* If that gives us a full block, process it. */
    if (*npartial == nblock)
    {
      process(ctx, partial);
      *npartial = 0;
    }
  }

  /* now nbytes < nblock or *npartial == 0. */

  /* If we have a full block of data, process it directly. */
  while (nbytes >= nblock)
  {
    /* Partial buffer must be empty, or we're ignoring extant data */
    assert(*npartial == 0);

    process(ctx, bufin);
    bufin += nblock;
    nbytes -= nblock;
  }

  /* Finally, if we have remaining data, buffer it. */
  while (nbytes)
  {
    size_t space = nblock - *npartial;
    size_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    /* If we started with *npartial, we must have copied it
     * in first. */
    assert(*npartial < nblock);
  }
}

void cf_blockwise_acc_byte(uint8_t *partial, size_t *npartial,
                           size_t nblock,
                           uint8_t byte, size_t nbytes,
                           cf_blockwise_in_fn process,
                           void *ctx)
{
  /* only memset the whole of the block once */
  int filled = 0;

  while (nbytes)
  {
    size_t start = *npartial;
    size_t count = MIN(nbytes, nblock - start);

    if (!filled)
      memset(partial + start, byte, count);

    if (start == 0 && count == nblock)
      filled = 1;

    if (start + count == nblock)
    {
      process(ctx, partial);
      *npartial = 0;
    } else {
      *npartial += count;
    }

    nbytes -= count;
  }
}

static void cf_blockwise_acc_pad(uint8_t *partial, size_t *npartial,
                                 size_t nblock,
                                 uint8_t fbyte, uint8_t mbyte, uint8_t lbyte,
                                 size_t nbytes,
                                 cf_blockwise_in_fn process,
                                 void *ctx)
{

  switch (nbytes)
  {
    case 0: break;
    case 1: fbyte ^= lbyte;
            cf_blockwise_accumulate(partial, npartial, nblock, &fbyte, 1, process, ctx);
            break;
    case 2:
            cf_blockwise_accumulate(partial, npartial, nblock, &fbyte, 1, process, ctx);
            cf_blockwise_accumulate(partial, npartial, nblock, &lbyte, 1, process, ctx);
            break;
    default:
            cf_blockwise_accumulate(partial, npartial, nblock, &fbyte, 1, process, ctx);

            /* If the middle and last bytes differ, then process the last byte separately.
             * Otherwise, just extend the middle block size. */
            if (lbyte != mbyte)
            {
              cf_blockwise_acc_byte(partial, npartial, nblock, mbyte, nbytes - 2, process, ctx);
              cf_blockwise_accumulate(partial, npartial, nblock, &lbyte, 1, process, ctx);
            } else {
              cf_blockwise_acc_byte(partial, npartial, nblock, mbyte, nbytes - 1, process, ctx);
            }

            break;
  }
}
/* --- SHA1 --- */

#define CF_SHA1_HASHSZ 20
#define CF_SHA1_BLOCKSZ 64

typedef struct
{
  uint32_t H[5];
  uint8_t partial[CF_SHA1_BLOCKSZ];
  size_t blocks;
  size_t npartial;
} cf_sha1_context;

typedef uint32_t cf_sha1_block[16];

static void cf_sha1_init(cf_sha1_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0x67452301;
  ctx->H[1] = 0xefcdab89;
  ctx->H[2] = 0x98badcfe;
  ctx->H[3] = 0x10325476;
  ctx->H[4] = 0xc3d2e1f0;
}

static void sha1_raw_transform(const uint32_t state_in[5],
                               uint32_t state_out[5],
                               const cf_sha1_block inp)
{
  uint32_t a = state_in[0],
           b = state_in[1],
           c = state_in[2],
           d = state_in[3],
           e = state_in[4];

  uint32_t W[80];

#define Wi(i) W[i] = inp[i]
#define Wn(n) W[n] = rotl32(W[n - 3] ^ W[n - 8] ^ W[n - 14] ^ W[n - 16], 1)

#define R0(v, w, x, y, z, i) z += ((w & (x ^ y)) ^ y) + W[i] + 0x5a827999 + rotl32(v, 5); w = rotl32(w, 30)
#define R1(v, w, x, y, z, i) z += (w ^ x ^ y) + W[i] + 0x6ed9eba1 + rotl32(v, 5); w = rotl32(w, 30)
#define R2(v, w, x, y, z, i) z += (((w | x) & y) | (w & x)) + W[i] + 0x8f1bbcdc + rotl32(v, 5); w = rotl32(w, 30)
#define R3(v, w, x, y, z, i) z += (w ^ x ^ y) + W[i] + 0xca62c1d6 + rotl32(v, 5); w = rotl32(w, 30)

  Wi(0);  R0(a, b, c, d, e, 0);
  Wi(1);  R0(e, a, b, c, d, 1);
  Wi(2);  R0(d, e, a, b, c, 2);
  Wi(3);  R0(c, d, e, a, b, 3);
  Wi(4);  R0(b, c, d, e, a, 4);
  Wi(5);  R0(a, b, c, d, e, 5);
  Wi(6);  R0(e, a, b, c, d, 6);
  Wi(7);  R0(d, e, a, b, c, 7);
  Wi(8);  R0(c, d, e, a, b, 8);
  Wi(9);  R0(b, c, d, e, a, 9);
  Wi(10); R0(a, b, c, d, e, 10);
  Wi(11); R0(e, a, b, c, d, 11);
  Wi(12); R0(d, e, a, b, c, 12);
  Wi(13); R0(c, d, e, a, b, 13);
  Wi(14); R0(b, c, d, e, a, 14);
  Wi(15); R0(a, b, c, d, e, 15);
  
  Wn(16); R0(e, a, b, c, d, 16);
  Wn(17); R0(d, e, a, b, c, 17);
  Wn(18); R0(c, d, e, a, b, 18);
  Wn(19); R0(b, c, d, e, a, 19);
  Wn(20); R1(a, b, c, d, e, 20);
  Wn(21); R1(e, a, b, c, d, 21);
  Wn(22); R1(d, e, a, b, c, 22);
  Wn(23); R1(c, d, e, a, b, 23);
  Wn(24); R1(b, c, d, e, a, 24);
  Wn(25); R1(a, b, c, d, e, 25);
  Wn(26); R1(e, a, b, c, d, 26);
  Wn(27); R1(d, e, a, b, c, 27);
  Wn(28); R1(c, d, e, a, b, 28);
  Wn(29); R1(b, c, d, e, a, 29);
  Wn(30); R1(a, b, c, d, e, 30);
  Wn(31); R1(e, a, b, c, d, 31);
  Wn(32); R1(d, e, a, b, c, 32);
  Wn(33); R1(c, d, e, a, b, 33);
  Wn(34); R1(b, c, d, e, a, 34);
  Wn(35); R1(a, b, c, d, e, 35);
  Wn(36); R1(e, a, b, c, d, 36);
  Wn(37); R1(d, e, a, b, c, 37);
  Wn(38); R1(c, d, e, a, b, 38);
  Wn(39); R1(b, c, d, e, a, 39);
  Wn(40); R2(a, b, c, d, e, 40);
  Wn(41); R2(e, a, b, c, d, 41);
  Wn(42); R2(d, e, a, b, c, 42);
  Wn(43); R2(c, d, e, a, b, 43);
  Wn(44); R2(b, c, d, e, a, 44);
  Wn(45); R2(a, b, c, d, e, 45);
  Wn(46); R2(e, a, b, c, d, 46);
  Wn(47); R2(d, e, a, b, c, 47);
  Wn(48); R2(c, d, e, a, b, 48);
  Wn(49); R2(b, c, d, e, a, 49);
  Wn(50); R2(a, b, c, d, e, 50);
  Wn(51); R2(e, a, b, c, d, 51);
  Wn(52); R2(d, e, a, b, c, 52);
  Wn(53); R2(c, d, e, a, b, 53);
  Wn(54); R2(b, c, d, e, a, 54);
  Wn(55); R2(a, b, c, d, e, 55);
  Wn(56); R2(e, a, b, c, d, 56);
  Wn(57); R2(d, e, a, b, c, 57);
  Wn(58); R2(c, d, e, a, b, 58);
  Wn(59); R2(b, c, d, e, a, 59);
  Wn(60); R3(a, b, c, d, e, 60);
  Wn(61); R3(e, a, b, c, d, 61);
  Wn(62); R3(d, e, a, b, c, 62);
  Wn(63); R3(c, d, e, a, b, 63);
  Wn(64); R3(b, c, d, e, a, 64);
  Wn(65); R3(a, b, c, d, e, 65);
  Wn(66); R3(e, a, b, c, d, 66);
  Wn(67); R3(d, e, a, b, c, 67);
  Wn(68); R3(c, d, e, a, b, 68);
  Wn(69); R3(b, c, d, e, a, 69);
  Wn(70); R3(a, b, c, d, e, 70);
  Wn(71); R3(e, a, b, c, d, 71);
  Wn(72); R3(d, e, a, b, c, 72);
  Wn(73); R3(c, d, e, a, b, 73);
  Wn(74); R3(b, c, d, e, a, 74);
  Wn(75); R3(a, b, c, d, e, 75);
  Wn(76); R3(e, a, b, c, d, 76);
  Wn(77); R3(d, e, a, b, c, 77);
  Wn(78); R3(c, d, e, a, b, 78);
  Wn(79); R3(b, c, d, e, a, 79);

  state_out[0] = a + state_in[0];
  state_out[1] = b + state_in[1];
  state_out[2] = c + state_in[2];
  state_out[3] = d + state_in[3];
  state_out[4] = e + state_in[4];

#undef R0
#undef R1
#undef R2
#undef R3
#undef Wi
#undef Wn
}

static void sha1_convert_input(cf_sha1_block inp32, const uint8_t inp[64])
{
  for (int i = 0; i < 64; i += 4)
    inp32[i >> 2] = read32_be(inp + i);
}

static void sha1_update_block(void *vctx, const uint8_t inp[64])
{
  cf_sha1_context *ctx = vctx;
  uint32_t inp32[16];
  sha1_convert_input(inp32, inp);
  sha1_raw_transform(ctx->H, ctx->H, inp32);
  ctx->blocks += 1;
}

static void sha1_convert_output(const uint32_t *restrict h, uint8_t *restrict out)
{
  write32_be(h[0], out);
  write32_be(h[1], out + 4);
  write32_be(h[2], out + 8);
  write32_be(h[3], out + 12);
  write32_be(h[4], out + 16);
}

static inline void sha1_xor(uint32_t *restrict out, const uint32_t *restrict in)
{
  out[0] ^= in[0];
  out[1] ^= in[1];
  out[2] ^= in[2];
  out[3] ^= in[3];
  out[4] ^= in[4];
}

static void cf_sha1_update(cf_sha1_context *ctx, const uint8_t *bytes, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          bytes, nbytes,
                          sha1_update_block, ctx);
}

static void cf_sha1_final(cf_sha1_context *ctx, uint8_t out[CF_SHA1_HASHSZ])
{
  uint32_t bytes = ctx->blocks * CF_SHA1_BLOCKSZ + ctx->npartial;
  uint32_t bits = bytes * 8;
  uint32_t padbytes = CF_SHA1_BLOCKSZ - ((bytes + 4) % CF_SHA1_BLOCKSZ);
  
  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha1_update_block, ctx);

  /* Hash length */
  uint8_t buf[4];
  write32_be(bits, buf);
  cf_sha1_update(ctx, buf, 4);
  assert(ctx->npartial == 0);

  sha1_convert_output(ctx->H, out);
}

#define _name       sha1
#define _blocksz    CF_SHA1_BLOCKSZ
#define _hashsz     CF_SHA1_HASHSZ
#define _ctx        cf_sha1_context
#define _blocktype  cf_sha1_block
#define _cvt_input  sha1_convert_input
#define _cvt_output sha1_convert_output
#define _init       cf_sha1_init
#define _update     cf_sha1_update
#define _final      cf_sha1_final
#define _transform  sha1_raw_transform
#define _xor        sha1_xor

//#include "core.inc.c"

#ifndef HMAC_CTX
# define GLUE3(a, b, c) a ## b ## c
# define HMAC_CTX(_name) GLUE3(HMAC_, _name, _ctx)
# define HMAC_INIT(_name) GLUE3(HMAC_, _name, _init)
# define HMAC_UPDATE(_name) GLUE3(HMAC_, _name, _update)
# define HMAC_FINAL(_name) GLUE3(HMAC_, _name, _final)

# define PBKDF2_F(_name) GLUE3(pbkdf2, _f_, _name)
# define PBKDF2(_name) GLUE3(pbkdf2, _, _name)
#endif

typedef struct {
  _ctx inner;
  _ctx outer;
} HMAC_CTX(_name);

static inline void HMAC_INIT(_name)(HMAC_CTX(_name) *ctx,
                                    const uint8_t *key, size_t nkey)
{
  /* Prepare key: */
  uint8_t k[_blocksz];

  /* Shorten long keys. */
  if (nkey > _blocksz)
  {
    _init(&ctx->inner);
    _update(&ctx->inner, key, nkey);
    _final(&ctx->inner, k);

    key = k;
    nkey = _hashsz;
  }

  /* Standard doesn't cover case where blocksz < hashsz. */
  assert(nkey <= _blocksz);

  /* Right zero-pad short keys. */
  if (k != key)
    memcpy(k, key, nkey);
  if (_blocksz > nkey)
    memset(k + nkey, 0, _blocksz - nkey);

  /* Start inner hash computation */
  uint8_t blk_inner[_blocksz];
  uint8_t blk_outer[_blocksz];

  for (size_t i = 0; i < _blocksz; i++)
  {
    blk_inner[i] = 0x36 ^ k[i];
    blk_outer[i] = 0x5c ^ k[i];
  }

  _init(&ctx->inner);
  _update(&ctx->inner, blk_inner, sizeof blk_inner);

  /* And outer. */
  _init(&ctx->outer);
  _update(&ctx->outer, blk_outer, sizeof blk_outer);
}

static inline void HMAC_UPDATE(_name)(HMAC_CTX(_name) *ctx,
                                      const void *data, size_t ndata)
{
  _update(&ctx->inner, data, ndata);
}

static inline void HMAC_FINAL(_name)(HMAC_CTX(_name) *ctx,
                                     uint8_t out[_hashsz])
{
  _final(&ctx->inner, out);
  _update(&ctx->outer, out, _hashsz);
  _final(&ctx->outer, out);
}


/* --- PBKDF2 --- */
static inline void PBKDF2_F(_name)(const HMAC_CTX(_name) *startctx,
                                   uint32_t counter,
                                   const uint8_t *salt, size_t nsalt,
                                   uint32_t iterations,
                                   uint8_t *out)
{
  uint8_t countbuf[4];
  write32_be(counter, countbuf);

  /* Prepare loop-invariant padding block. */
  uint8_t Ubytes[_blocksz];
  md_pad(Ubytes, _blocksz, _hashsz, _blocksz + _hashsz);

  /* First iteration:
   *   U_1 = PRF(P, S || INT_32_BE(i))
   */
  HMAC_CTX(_name) ctx = *startctx;
  HMAC_UPDATE(_name)(&ctx, salt, nsalt);
  HMAC_UPDATE(_name)(&ctx, countbuf, sizeof countbuf);
  HMAC_FINAL(_name)(&ctx, Ubytes);
  _ctx result = ctx.outer;

  /* Convert the first U_1 term to correct endianness.
   * The inner loop is native-endian. */
  _blocktype Ublock;
  _cvt_input(Ublock, Ubytes);

  /* Subsequent iterations:
   *   U_c = PRF(P, U_{c-1})
   *
   * At this point, Ublock contains U_1 plus MD padding, in native
   * byte order.
   */
  for (uint32_t i = 1; i < iterations; i++)
  {
    /* Complete inner hash with previous U (stored at the start of Ublock)
     *
     * Put the result again at the start of Ublock. */
    _transform(startctx->inner.H, Ublock, Ublock);

    /* Complete outer hash with inner output */
    _transform(startctx->outer.H, Ublock, Ublock);

    /* Collect ultimate result */
    _xor(result.H, Ublock);
  }

  /* Reform result into output buffer. */
  _cvt_output(result.H, out);
}

static inline void PBKDF2(_name)(const uint8_t *pw, size_t npw,
                   const uint8_t *salt, size_t nsalt,
                   uint32_t iterations,
                   uint8_t *out, size_t nout)
{
  assert(iterations);
  assert(out && nout);

  /* Starting point for inner loop. */
  HMAC_CTX(_name) ctx;
  HMAC_INIT(_name)(&ctx, pw, npw);

  /* How many blocks do we need? */
  uint32_t blocks_needed = (nout + _hashsz - 1) / _hashsz;

  OPENMP_PARALLEL_FOR
  for (uint32_t counter = 1; counter <= blocks_needed; counter++)
  {
    uint8_t block[_hashsz];
    PBKDF2_F(_name)(&ctx, counter, salt, nsalt, iterations, block);

    size_t offset = (counter - 1) * _hashsz;
    size_t taken = MIN(nout - offset, _hashsz);
    memcpy(out + offset, block, taken);
  }
}



#undef _name
#undef _blocksz
#undef _hashsz
#undef _ctx
#undef _blocktype
#undef _cvt_input
#undef _cvt_output
#undef _init
#undef _update
#undef _final
#undef _transform
#undef _xor
/* --- SHA256 --- */
#define CF_SHA256_BLOCKSZ 64
#define CF_SHA256_HASHSZ 32

typedef struct
{
  uint32_t H[8];
  uint8_t partial[CF_SHA256_BLOCKSZ];
  uint32_t blocks;
  size_t npartial;
} cf_sha256_context;

typedef uint32_t cf_sha256_block[16];

static void cf_sha256_init(cf_sha256_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0x6a09e667;
  ctx->H[1] = 0xbb67ae85;
  ctx->H[2] = 0x3c6ef372;
  ctx->H[3] = 0xa54ff53a;
  ctx->H[4] = 0x510e527f;
  ctx->H[5] = 0x9b05688c;
  ctx->H[6] = 0x1f83d9ab;
  ctx->H[7] = 0x5be0cd19;
}

#if defined(__GNUC__) && defined(__x86_64__)
extern void fastpbkdf2_sha256_sse4(const uint32_t state_in[8],
                                   uint32_t state_out[8],
                                   const cf_sha256_block inp);
extern void fastpbkdf2_sha256_avx1(const uint32_t state_in[8],
                                   uint32_t state_out[8],
                                   const cf_sha256_block inp);
# define sha256_raw_transform fastpbkdf2_sha256_sse4
#else
static void sha256_raw_transform(const uint32_t state_in[8],
                                 uint32_t state_out[8],
                                 const cf_sha256_block inp)
{
  uint32_t W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, Wa,
           Wb, Wc, Wd, We, Wf;

  uint32_t a = state_in[0],
           b = state_in[1],
           c = state_in[2],
           d = state_in[3],
           e = state_in[4],
           f = state_in[5],
           g = state_in[6],
           h = state_in[7];
           
# define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define BSIG0(x) (rotr32((x), 2) ^ rotr32((x), 13) ^ rotr32((x), 22))
# define BSIG1(x) (rotr32((x), 6) ^ rotr32((x), 11) ^ rotr32((x), 25))
# define SSIG0(x) (rotr32((x), 7) ^ rotr32((x), 18) ^ ((x) >> 3))
# define SSIG1(x) (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))

# define W(Wn2, Wn7, Wn15, Wn16) SSIG1(Wn2) + Wn7 + SSIG0(Wn15) + Wn16

# define Winit() \
  W0 = inp[0];  W1 = inp[1];  W2 = inp[2];  W3 = inp[3];  \
  W4 = inp[4];  W5 = inp[5];  W6 = inp[6];  W7 = inp[7];  \
  W8 = inp[8];  W9 = inp[9];  Wa = inp[10]; Wb = inp[11]; \
  Wc = inp[12]; Wd = inp[13]; We = inp[14]; Wf = inp[15]

# define Wstep() \
  W0 = W(We, W9, W1, W0);    W1 = W(Wf, Wa, W2, W1);  \
  W2 = W(W0, Wb, W3, W2);    W3 = W(W1, Wc, W4, W3);  \
  W4 = W(W2, Wd, W5, W4);    W5 = W(W3, We, W6, W5);  \
  W6 = W(W4, Wf, W7, W6);    W7 = W(W5, W0, W8, W7);  \
  W8 = W(W6, W1, W9, W8);    W9 = W(W7, W2, Wa, W9);  \
  Wa = W(W8, W3, Wb, Wa);    Wb = W(W9, W4, Wc, Wb);  \
  Wc = W(Wa, W5, Wd, Wc);    Wd = W(Wb, W6, We, Wd);  \
  We = W(Wc, W7, Wf, We);    Wf = W(Wd, W8, W0, Wf)

# define R(a, b, c, d, e, f, g, h, W, K)                           \
      do {                                                         \
        uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K + W;          \
        uint32_t T2 = BSIG0(a) + MAJ(a, b, c);                     \
        d += T1;                                                   \
        h = T1 + T2;                                               \
      } while (0)
  
  /* For best locality/reg allocation, compute 16 terms
   * of W at once. */
  Winit();
  R(a, b, c, d, e, f, g, h, W0, 0x428a2f98);
  R(h, a, b, c, d, e, f, g, W1, 0x71374491);
  R(g, h, a, b, c, d, e, f, W2, 0xb5c0fbcf);
  R(f, g, h, a, b, c, d, e, W3, 0xe9b5dba5);
  R(e, f, g, h, a, b, c, d, W4, 0x3956c25b);
  R(d, e, f, g, h, a, b, c, W5, 0x59f111f1);
  R(c, d, e, f, g, h, a, b, W6, 0x923f82a4);
  R(b, c, d, e, f, g, h, a, W7, 0xab1c5ed5);
  R(a, b, c, d, e, f, g, h, W8, 0xd807aa98);
  R(h, a, b, c, d, e, f, g, W9, 0x12835b01);
  R(g, h, a, b, c, d, e, f, Wa, 0x243185be);
  R(f, g, h, a, b, c, d, e, Wb, 0x550c7dc3);
  R(e, f, g, h, a, b, c, d, Wc, 0x72be5d74);
  R(d, e, f, g, h, a, b, c, Wd, 0x80deb1fe);
  R(c, d, e, f, g, h, a, b, We, 0x9bdc06a7);
  R(b, c, d, e, f, g, h, a, Wf, 0xc19bf174);
 
  Wstep();
  R(a, b, c, d, e, f, g, h, W0, 0xe49b69c1);
  R(h, a, b, c, d, e, f, g, W1, 0xefbe4786);
  R(g, h, a, b, c, d, e, f, W2, 0x0fc19dc6);
  R(f, g, h, a, b, c, d, e, W3, 0x240ca1cc);
  R(e, f, g, h, a, b, c, d, W4, 0x2de92c6f);
  R(d, e, f, g, h, a, b, c, W5, 0x4a7484aa);
  R(c, d, e, f, g, h, a, b, W6, 0x5cb0a9dc);
  R(b, c, d, e, f, g, h, a, W7, 0x76f988da);
  R(a, b, c, d, e, f, g, h, W8, 0x983e5152);
  R(h, a, b, c, d, e, f, g, W9, 0xa831c66d);
  R(g, h, a, b, c, d, e, f, Wa, 0xb00327c8);
  R(f, g, h, a, b, c, d, e, Wb, 0xbf597fc7);
  R(e, f, g, h, a, b, c, d, Wc, 0xc6e00bf3);
  R(d, e, f, g, h, a, b, c, Wd, 0xd5a79147);
  R(c, d, e, f, g, h, a, b, We, 0x06ca6351);
  R(b, c, d, e, f, g, h, a, Wf, 0x14292967);
  
  Wstep();
  R(a, b, c, d, e, f, g, h, W0, 0x27b70a85);
  R(h, a, b, c, d, e, f, g, W1, 0x2e1b2138);
  R(g, h, a, b, c, d, e, f, W2, 0x4d2c6dfc);
  R(f, g, h, a, b, c, d, e, W3, 0x53380d13);
  R(e, f, g, h, a, b, c, d, W4, 0x650a7354);
  R(d, e, f, g, h, a, b, c, W5, 0x766a0abb);
  R(c, d, e, f, g, h, a, b, W6, 0x81c2c92e);
  R(b, c, d, e, f, g, h, a, W7, 0x92722c85);
  R(a, b, c, d, e, f, g, h, W8, 0xa2bfe8a1);
  R(h, a, b, c, d, e, f, g, W9, 0xa81a664b);
  R(g, h, a, b, c, d, e, f, Wa, 0xc24b8b70);
  R(f, g, h, a, b, c, d, e, Wb, 0xc76c51a3);
  R(e, f, g, h, a, b, c, d, Wc, 0xd192e819);
  R(d, e, f, g, h, a, b, c, Wd, 0xd6990624);
  R(c, d, e, f, g, h, a, b, We, 0xf40e3585);
  R(b, c, d, e, f, g, h, a, Wf, 0x106aa070);
 
  Wstep();
  R(a, b, c, d, e, f, g, h, W0, 0x19a4c116);
  R(h, a, b, c, d, e, f, g, W1, 0x1e376c08);
  R(g, h, a, b, c, d, e, f, W2, 0x2748774c);
  R(f, g, h, a, b, c, d, e, W3, 0x34b0bcb5);
  R(e, f, g, h, a, b, c, d, W4, 0x391c0cb3);
  R(d, e, f, g, h, a, b, c, W5, 0x4ed8aa4a);
  R(c, d, e, f, g, h, a, b, W6, 0x5b9cca4f);
  R(b, c, d, e, f, g, h, a, W7, 0x682e6ff3);
  R(a, b, c, d, e, f, g, h, W8, 0x748f82ee);
  R(h, a, b, c, d, e, f, g, W9, 0x78a5636f);
  R(g, h, a, b, c, d, e, f, Wa, 0x84c87814);
  R(f, g, h, a, b, c, d, e, Wb, 0x8cc70208);
  R(e, f, g, h, a, b, c, d, Wc, 0x90befffa);
  R(d, e, f, g, h, a, b, c, Wd, 0xa4506ceb);
  R(c, d, e, f, g, h, a, b, We, 0xbef9a3f7);
  R(b, c, d, e, f, g, h, a, Wf, 0xc67178f2);

  state_out[0] = state_in[0] + a;
  state_out[1] = state_in[1] + b;
  state_out[2] = state_in[2] + c;
  state_out[3] = state_in[3] + d;
  state_out[4] = state_in[4] + e;
  state_out[5] = state_in[5] + f;
  state_out[6] = state_in[6] + g;
  state_out[7] = state_in[7] + h;
  
#undef CH
#undef MAJ
#undef BSIG0
#undef BSIG1
#undef SSIG0
#undef SSIG1
#undef W
#undef Wstep
#undef Winit
#undef R
}
#endif

static void sha256_convert_input(cf_sha256_block inp32, const uint8_t inp[CF_SHA256_BLOCKSZ])
{
  for (int i = 0; i < 64; i += 4)
    inp32[i >> 2] = read32_be(inp + i);
}

static void sha256_update_block(void *vctx, const uint8_t *inp)
{
  cf_sha256_context *ctx = vctx;
  cf_sha256_block inp32;
  sha256_convert_input(inp32, inp);
  sha256_raw_transform(ctx->H, ctx->H, inp32);
  ctx->blocks += 1;
}

static void cf_sha256_update(cf_sha256_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          data, nbytes,
                          sha256_update_block, ctx);
}

static void sha256_convert_output(const uint32_t H[8],
                                  uint8_t hash[CF_SHA256_HASHSZ])
{
  write32_be(H[0], hash + 0);
  write32_be(H[1], hash + 4);
  write32_be(H[2], hash + 8);
  write32_be(H[3], hash + 12);
  write32_be(H[4], hash + 16);
  write32_be(H[5], hash + 20);
  write32_be(H[6], hash + 24);
  write32_be(H[7], hash + 28);
}

static void sha256_xor(uint32_t *restrict out, const uint32_t *restrict in)
{
  out[0] ^= in[0];
  out[1] ^= in[1];
  out[2] ^= in[2];
  out[3] ^= in[3];
  out[4] ^= in[4];
  out[5] ^= in[5];
  out[6] ^= in[6];
  out[7] ^= in[7];
}

void cf_sha256_final(cf_sha256_context *ctx, uint8_t hash[CF_SHA256_HASHSZ])
{
  uint32_t digested_bytes = ctx->blocks;
  digested_bytes = digested_bytes * CF_SHA256_BLOCKSZ + ctx->npartial;
  uint32_t digested_bits = digested_bytes * 8;

  size_t padbytes = CF_SHA256_BLOCKSZ - ((digested_bytes + 4) % CF_SHA256_BLOCKSZ);

  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha256_update_block, ctx);

  /* Now hash length. */
  uint8_t buf[4];
  write32_be(digested_bits, buf);
  cf_sha256_update(ctx, buf, 4);
  assert(ctx->npartial == 0);

  sha256_convert_output(ctx->H, hash);
}

#define _name       sha256
#define _blocksz    CF_SHA256_BLOCKSZ
#define _hashsz     CF_SHA256_HASHSZ
#define _ctx        cf_sha256_context
#define _blocktype  cf_sha256_block
#define _cvt_input  sha256_convert_input
#define _cvt_output sha256_convert_output
#define _init       cf_sha256_init
#define _update     cf_sha256_update
#define _final      cf_sha256_final
#define _transform  sha256_raw_transform
#define _xor        sha256_xor

#ifndef HMAC_CTX
# define GLUE3(a, b, c) a ## b ## c
# define HMAC_CTX(_name) GLUE3(HMAC_, _name, _ctx)
# define HMAC_INIT(_name) GLUE3(HMAC_, _name, _init)
# define HMAC_UPDATE(_name) GLUE3(HMAC_, _name, _update)
# define HMAC_FINAL(_name) GLUE3(HMAC_, _name, _final)

# define PBKDF2_F(_name) GLUE3(pbkdf2, _f_, _name)
# define PBKDF2(_name) GLUE3(pbkdf2, _, _name)
#endif

typedef struct {
  _ctx inner;
  _ctx outer;
} HMAC_CTX(_name);

static inline void HMAC_INIT(_name)(HMAC_CTX(_name) *ctx,
                                    const uint8_t *key, size_t nkey)
{
  /* Prepare key: */
  uint8_t k[_blocksz];

  /* Shorten long keys. */
  if (nkey > _blocksz)
  {
    _init(&ctx->inner);
    _update(&ctx->inner, key, nkey);
    _final(&ctx->inner, k);

    key = k;
    nkey = _hashsz;
  }

  /* Standard doesn't cover case where blocksz < hashsz. */
  assert(nkey <= _blocksz);

  /* Right zero-pad short keys. */
  if (k != key)
    memcpy(k, key, nkey);
  if (_blocksz > nkey)
    memset(k + nkey, 0, _blocksz - nkey);

  /* Start inner hash computation */
  uint8_t blk_inner[_blocksz];
  uint8_t blk_outer[_blocksz];

  for (size_t i = 0; i < _blocksz; i++)
  {
    blk_inner[i] = 0x36 ^ k[i];
    blk_outer[i] = 0x5c ^ k[i];
  }

  _init(&ctx->inner);
  _update(&ctx->inner, blk_inner, sizeof blk_inner);

  /* And outer. */
  _init(&ctx->outer);
  _update(&ctx->outer, blk_outer, sizeof blk_outer);
}

static inline void HMAC_UPDATE(_name)(HMAC_CTX(_name) *ctx,
                                      const void *data, size_t ndata)
{
  _update(&ctx->inner, data, ndata);
}

static inline void HMAC_FINAL(_name)(HMAC_CTX(_name) *ctx,
                                     uint8_t out[_hashsz])
{
  _final(&ctx->inner, out);
  _update(&ctx->outer, out, _hashsz);
  _final(&ctx->outer, out);
}


/* --- PBKDF2 --- */
static inline void PBKDF2_F(_name)(const HMAC_CTX(_name) *startctx,
                                   uint32_t counter,
                                   const uint8_t *salt, size_t nsalt,
                                   uint32_t iterations,
                                   uint8_t *out)
{
  uint8_t countbuf[4];
  write32_be(counter, countbuf);

  /* Prepare loop-invariant padding block. */
  uint8_t Ubytes[_blocksz];
  md_pad(Ubytes, _blocksz, _hashsz, _blocksz + _hashsz);

  /* First iteration:
   *   U_1 = PRF(P, S || INT_32_BE(i))
   */
  HMAC_CTX(_name) ctx = *startctx;
  HMAC_UPDATE(_name)(&ctx, salt, nsalt);
  HMAC_UPDATE(_name)(&ctx, countbuf, sizeof countbuf);
  HMAC_FINAL(_name)(&ctx, Ubytes);
  _ctx result = ctx.outer;

  /* Convert the first U_1 term to correct endianness.
   * The inner loop is native-endian. */
  _blocktype Ublock;
  _cvt_input(Ublock, Ubytes);

  /* Subsequent iterations:
   *   U_c = PRF(P, U_{c-1})
   *
   * At this point, Ublock contains U_1 plus MD padding, in native
   * byte order.
   */
  for (uint32_t i = 1; i < iterations; i++)
  {
    /* Complete inner hash with previous U (stored at the start of Ublock)
     *
     * Put the result again at the start of Ublock. */
    _transform(startctx->inner.H, Ublock, Ublock);

    /* Complete outer hash with inner output */
    _transform(startctx->outer.H, Ublock, Ublock);

    /* Collect ultimate result */
    _xor(result.H, Ublock);
  }

  /* Reform result into output buffer. */
  _cvt_output(result.H, out);
}

static inline void PBKDF2(_name)(const uint8_t *pw, size_t npw,
                   const uint8_t *salt, size_t nsalt,
                   uint32_t iterations,
                   uint8_t *out, size_t nout)
{
  assert(iterations);
  assert(out && nout);

  /* Starting point for inner loop. */
  HMAC_CTX(_name) ctx;
  HMAC_INIT(_name)(&ctx, pw, npw);

  /* How many blocks do we need? */
  uint32_t blocks_needed = (nout + _hashsz - 1) / _hashsz;

  OPENMP_PARALLEL_FOR
  for (uint32_t counter = 1; counter <= blocks_needed; counter++)
  {
    uint8_t block[_hashsz];
    PBKDF2_F(_name)(&ctx, counter, salt, nsalt, iterations, block);

    size_t offset = (counter - 1) * _hashsz;
    size_t taken = MIN(nout - offset, _hashsz);
    memcpy(out + offset, block, taken);
  }
}



#undef _name
#undef _blocksz
#undef _hashsz
#undef _ctx
#undef _blocktype
#undef _cvt_input
#undef _cvt_output
#undef _init
#undef _update
#undef _final
#undef _transform
#undef _xor

//#include "sha512.inc.c"

void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                          const uint8_t *salt, size_t nsalt,
                          uint32_t iterations,
                          uint8_t *out, size_t nout)
{
  PBKDF2(sha1)(pw, npw, salt, nsalt, iterations, out, nout);
}

void fastpbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout)
{
  PBKDF2(sha256)(pw, npw, salt, nsalt, iterations, out, nout);
}

//void fastpbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
//                            const uint8_t *salt, size_t nsalt,
//                            uint32_t iterations,
//                            uint8_t *out, size_t nout)
//{
//  PBKDF2(sha512)(pw, npw, salt, nsalt, iterations, out, nout);
//}


#if defined (__CC_ARM)
#pragma pop
#elif defined (__GNUC__)
#pragma GCC pop_options
#endif

