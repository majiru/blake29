/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/


#include <u.h>
#include <libc.h>

#include "blake2.h"
#include "blake2-impl.h"

#define PARALLELISM_DEGREE 8

/*
  blake2sp_init_param defaults to setting the expecting output length
  from the digest_length parameter block field.

  In some cases, however, we do not want this, as the output length
  of these instances is given by inner_length instead.
*/
static int blake2sp_init_leaf_param( blake2s_state *S, const blake2s_param *P )
{
  int err = blake2s_init_param(S, P);
  S->outlen = P->inner_length;
  return err;
}

static int blake2sp_init_leaf( blake2s_state *S, u64int outlen, u64int keylen, u64int offset )
{
  blake2s_param P[1];
  P->digest_length = (u8int)outlen;
  P->key_length = (u8int)keylen;
  P->fanout = PARALLELISM_DEGREE;
  P->depth = 2;
  store32( &P->leaf_length, 0 );
  store32( &P->node_offset, offset );
  store16( &P->xof_length, 0 );
  P->node_depth = 0;
  P->inner_length = BLAKE2S_OUTBYTES;
  memset( P->salt, 0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2sp_init_leaf_param( S, P );
}

static int blake2sp_init_root( blake2s_state *S, u64int outlen, u64int keylen )
{
  blake2s_param P[1];
  P->digest_length = (u8int)outlen;
  P->key_length = (u8int)keylen;
  P->fanout = PARALLELISM_DEGREE;
  P->depth = 2;
  store32( &P->leaf_length, 0 );
  store32( &P->node_offset, 0 );
  store16( &P->xof_length, 0 );
  P->node_depth = 1;
  P->inner_length = BLAKE2S_OUTBYTES;
  memset( P->salt, 0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2s_init_param( S, P );
}


int blake2sp_init( blake2sp_state *S, u64int outlen )
{
  u64int i;

  if( !outlen || outlen > BLAKE2S_OUTBYTES ) return -1;

  memset( S->buf, 0, sizeof( S->buf ) );
  S->buflen = 0;
  S->outlen = outlen;

  if( blake2sp_init_root( S->R, outlen, 0 ) < 0 )
    return -1;

  for( i = 0; i < PARALLELISM_DEGREE; ++i )
    if( blake2sp_init_leaf( S->S[i], outlen, 0, i ) < 0 ) return -1;

  S->R->last_node = 1;
  S->S[PARALLELISM_DEGREE - 1]->last_node = 1;
  return 0;
}

int blake2sp_init_key( blake2sp_state *S, u64int outlen, const void *key, u64int keylen )
{
  u64int i;

  if( !outlen || outlen > BLAKE2S_OUTBYTES ) return -1;

  if( !key || !keylen || keylen > BLAKE2S_KEYBYTES ) return -1;

  memset( S->buf, 0, sizeof( S->buf ) );
  S->buflen = 0;
  S->outlen = outlen;

  if( blake2sp_init_root( S->R, outlen, keylen ) < 0 )
    return -1;

  for( i = 0; i < PARALLELISM_DEGREE; ++i )
    if( blake2sp_init_leaf( S->S[i], outlen, keylen, i ) < 0 ) return -1;

  S->R->last_node = 1;
  S->S[PARALLELISM_DEGREE - 1]->last_node = 1;
  {
    u8int block[BLAKE2S_BLOCKBYTES];
    memset( block, 0, BLAKE2S_BLOCKBYTES );
    memcpy( block, key, keylen );

    for( i = 0; i < PARALLELISM_DEGREE; ++i )
      blake2s_update( S->S[i], block, BLAKE2S_BLOCKBYTES );

    memset(block, 0, BLAKE2S_BLOCKBYTES); /* Burn the key from stack */
  }
  return 0;
}


int blake2sp_update( blake2sp_state *S, const void *pin, u64int inlen )
{
  const unsigned char * in = (const unsigned char *)pin;
  u64int left = S->buflen;
  u64int fill = sizeof( S->buf ) - left;
  u64int i;

  if( left && inlen >= fill )
  {
    memcpy( S->buf + left, in, fill );

    for( i = 0; i < PARALLELISM_DEGREE; ++i )
      blake2s_update( S->S[i], S->buf + i * BLAKE2S_BLOCKBYTES, BLAKE2S_BLOCKBYTES );

    in += fill;
    inlen -= fill;
    left = 0;
  }

#if defined(_OPENMP)
  #pragma omp parallel shared(S), num_threads(PARALLELISM_DEGREE)
#else
  for( i = 0; i < PARALLELISM_DEGREE; ++i )
#endif
  {
#if defined(_OPENMP)
    u64int      i = omp_get_thread_num();
#endif
    u64int inlen__ = inlen;
    const unsigned char *in__ = ( const unsigned char * )in;
    in__ += i * BLAKE2S_BLOCKBYTES;

    while( inlen__ >= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES )
    {
      blake2s_update( S->S[i], in__, BLAKE2S_BLOCKBYTES );
      in__ += PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
      inlen__ -= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
    }
  }

  in += inlen - inlen % ( PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES );
  inlen %= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;

  if( inlen > 0 )
    memcpy( S->buf + left, in, inlen );

  S->buflen = left + inlen;
  return 0;
}


int blake2sp_final( blake2sp_state *S, void *out, u64int outlen )
{
  u8int hash[PARALLELISM_DEGREE][BLAKE2S_OUTBYTES];
  u64int i;

  if(out == nil || outlen < S->outlen) {
    return -1;
  }

  for( i = 0; i < PARALLELISM_DEGREE; ++i )
  {
    if( S->buflen > i * BLAKE2S_BLOCKBYTES )
    {
      u64int left = S->buflen - i * BLAKE2S_BLOCKBYTES;

      if( left > BLAKE2S_BLOCKBYTES ) left = BLAKE2S_BLOCKBYTES;

      blake2s_update( S->S[i], S->buf + i * BLAKE2S_BLOCKBYTES, left );
    }

    blake2s_final( S->S[i], hash[i], BLAKE2S_OUTBYTES );
  }

  for( i = 0; i < PARALLELISM_DEGREE; ++i )
    blake2s_update( S->R, hash[i], BLAKE2S_OUTBYTES );

  return blake2s_final( S->R, out, S->outlen );
}


int blake2sp( void *out, u64int outlen, const void *in, u64int inlen, const void *key, u64int keylen )
{
  u8int hash[PARALLELISM_DEGREE][BLAKE2S_OUTBYTES];
  blake2s_state S[PARALLELISM_DEGREE][1];
  blake2s_state FS[1];
  u64int i;

  /* Verify parameters */
  if ( nil == in && inlen > 0 ) return -1;

  if ( nil == out ) return -1;

  if ( nil == key && keylen > 0) return -1;

  if( !outlen || outlen > BLAKE2S_OUTBYTES ) return -1;

  if( keylen > BLAKE2S_KEYBYTES ) return -1;

  for( i = 0; i < PARALLELISM_DEGREE; ++i )
    if( blake2sp_init_leaf( S[i], outlen, keylen, i ) < 0 ) return -1;

  S[PARALLELISM_DEGREE - 1]->last_node = 1; /* mark last node */

  if( keylen > 0 )
  {
    u8int block[BLAKE2S_BLOCKBYTES];
    memset( block, 0, BLAKE2S_BLOCKBYTES );
    memcpy( block, key, keylen );

    for( i = 0; i < PARALLELISM_DEGREE; ++i )
      blake2s_update( S[i], block, BLAKE2S_BLOCKBYTES );

    memset( block, 0, BLAKE2S_BLOCKBYTES ); /* Burn the key from stack */
  }

#if defined(_OPENMP)
  #pragma omp parallel shared(S,hash), num_threads(PARALLELISM_DEGREE)
#else

  for( i = 0; i < PARALLELISM_DEGREE; ++i )
#endif
  {
#if defined(_OPENMP)
    u64int      i = omp_get_thread_num();
#endif
    u64int inlen__ = inlen;
    const unsigned char *in__ = ( const unsigned char * )in;
    in__ += i * BLAKE2S_BLOCKBYTES;

    while( inlen__ >= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES )
    {
      blake2s_update( S[i], in__, BLAKE2S_BLOCKBYTES );
      in__ += PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
      inlen__ -= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
    }

    if( inlen__ > i * BLAKE2S_BLOCKBYTES )
    {
      const u64int left = inlen__ - i * BLAKE2S_BLOCKBYTES;
      const u64int len = left <= BLAKE2S_BLOCKBYTES ? left : BLAKE2S_BLOCKBYTES;
      blake2s_update( S[i], in__, len );
    }

    blake2s_final( S[i], hash[i], BLAKE2S_OUTBYTES );
  }

  if( blake2sp_init_root( FS, outlen, keylen ) < 0 )
    return -1;

  FS->last_node = 1;

  for( i = 0; i < PARALLELISM_DEGREE; ++i )
    blake2s_update( FS, hash[i], BLAKE2S_OUTBYTES );

  return blake2s_final( FS, out, outlen );
}



#if defined(BLAKE2SP_SELFTEST)
#include <string.h>
#include "blake2-kat.h"
int main( void )
{
  u8int key[BLAKE2S_KEYBYTES];
  u8int buf[BLAKE2_KAT_LENGTH];
  u64int i, step;

  for( i = 0; i < BLAKE2S_KEYBYTES; ++i )
    key[i] = ( u8int )i;

  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
    buf[i] = ( u8int )i;

  /* Test simple API */
  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
  {
    u8int hash[BLAKE2S_OUTBYTES];
    blake2sp( hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES );

    if( 0 != memcmp( hash, blake2sp_keyed_kat[i], BLAKE2S_OUTBYTES ) )
    {
      goto fail;
    }
  }

  /* Test streaming API */
  for(step = 1; step < BLAKE2S_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      u8int hash[BLAKE2S_OUTBYTES];
      blake2sp_state S;
      u8int * p = buf;
      u64int mlen = i;
      int err = 0;

      if( (err = blake2sp_init_key(&S, BLAKE2S_OUTBYTES, key, BLAKE2S_KEYBYTES)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = blake2sp_update(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = blake2sp_update(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = blake2sp_final(&S, hash, BLAKE2S_OUTBYTES)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, blake2sp_keyed_kat[i], BLAKE2S_OUTBYTES)) {
        goto fail;
      }
    }
  }

  print("ok\n");
  exits(nil);
  return 0;
fail:
  print("error\n");
  return -1;
}
#endif
