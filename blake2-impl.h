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


static u32int load32( const void *src )
{
  const u8int *p = ( const u8int * )src;
  return (( u32int )( p[0] ) <<  0) |
         (( u32int )( p[1] ) <<  8) |
         (( u32int )( p[2] ) << 16) |
         (( u32int )( p[3] ) << 24) ;
}

static u64int load64( const void *src )
{

  const u8int *p = ( const u8int * )src;
  return (( u64int )( p[0] ) <<  0) |
         (( u64int )( p[1] ) <<  8) |
         (( u64int )( p[2] ) << 16) |
         (( u64int )( p[3] ) << 24) |
         (( u64int )( p[4] ) << 32) |
         (( u64int )( p[5] ) << 40) |
         (( u64int )( p[6] ) << 48) |
         (( u64int )( p[7] ) << 56) ;
}

static u16int load16( const void *src )
{

  const u8int *p = ( const u8int * )src;
  return ( u16int )((( u32int )( p[0] ) <<  0) |
                      (( u32int )( p[1] ) <<  8));
}

static void store16( void *dst, u16int w )
{

  u8int *p = ( u8int * )dst;
  *p++ = ( u8int )w; w >>= 8;
  *p++ = ( u8int )w;
}

static void store32( void *dst, u32int w )
{

  u8int *p = ( u8int * )dst;
  p[0] = (u8int)(w >>  0);
  p[1] = (u8int)(w >>  8);
  p[2] = (u8int)(w >> 16);
  p[3] = (u8int)(w >> 24);
}

static void store64( void *dst, u64int w )
{

  u8int *p = ( u8int * )dst;
  p[0] = (u8int)(w >>  0);
  p[1] = (u8int)(w >>  8);
  p[2] = (u8int)(w >> 16);
  p[3] = (u8int)(w >> 24);
  p[4] = (u8int)(w >> 32);
  p[5] = (u8int)(w >> 40);
  p[6] = (u8int)(w >> 48);
  p[7] = (u8int)(w >> 56);
}

static u64int load48( const void *src )
{
  const u8int *p = ( const u8int * )src;
  return (( u64int )( p[0] ) <<  0) |
         (( u64int )( p[1] ) <<  8) |
         (( u64int )( p[2] ) << 16) |
         (( u64int )( p[3] ) << 24) |
         (( u64int )( p[4] ) << 32) |
         (( u64int )( p[5] ) << 40) ;
}

static void store48( void *dst, u64int w )
{
  u8int *p = ( u8int * )dst;
  p[0] = (u8int)(w >>  0);
  p[1] = (u8int)(w >>  8);
  p[2] = (u8int)(w >> 16);
  p[3] = (u8int)(w >> 24);
  p[4] = (u8int)(w >> 32);
  p[5] = (u8int)(w >> 40);
}

static u32int rotr32( const u32int w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 32 - c ) );
}

static u64int rotr64( const u64int w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 64 - c ) );
}



