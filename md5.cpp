/* MD5
 converted to C++ class by Frank Thilo (thilo@unix-ag.org)
 for bzflag (http://www.bzflag.org)
 
   based on:
 
   md5.h and md5.c
   reference implemantion of RFC 1321
 
   Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.
 
License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.
 
License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.
 
RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.
 
These notices must be retained in any copies of any part of this
documentation and/or software.
 
*/
 
/* interface header */
#include "md5.h"
 
/* system implementation headers */
#include <cstdio>
 
 
// Constants for MD5Transform routine.
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21
 
///////////////////////////////////////////////
 
// F, G, H and I are basic MD5 functions.
inline MD5::uint4 MD5::F(uint4 x, uint4 y, uint4 z) {
  return x&y | ~x&z;
}
 
inline MD5::uint4 MD5::G(uint4 x, uint4 y, uint4 z) {
  return x&z | y&~z;
}
 
inline MD5::uint4 MD5::H(uint4 x, uint4 y, uint4 z) {
  return x^y^z;
}
 
inline MD5::uint4 MD5::I(uint4 x, uint4 y, uint4 z) {
  return y ^ (x | ~z);
}
 
// rotate_left rotates x left n bits.
inline MD5::uint4 MD5::rotate_left(uint4 x, int n) {
  return (x << n) | (x >> (32-n));
}
 
// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline void MD5::FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a+ F(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a + G(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a + H(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a + I(b,c,d) + x + ac, s) + b;
}
 
//////////////////////////////////////////////
 
// default ctor, just initailize
/*MD5::MD5()
{
  init();
}*/
 
//////////////////////////////////////////////
 
// nifty shortcut ctor, compute MD5 for string and finalize it right away
MD5::MD5(const std::string &text, uint4 precomputed[64], uint4 state[4])
{
  for (int i=0; i<64; i++){
      this->precomputed[i]=precomputed[i];
  }
  init(state);
  update(text.c_str(), text.length());
  finalize();
}
 
//////////////////////////////
 
void MD5::init(uint4 state[4])
{
  finalized=false;
 
  count[0] = 0;
  count[1] = 0;
 
  // load magic initialization constants.
  this->state[0] = state[0];
  this->state[1] = state[1];
  this->state[2] = state[2];
  this->state[3] = state[3];
}
 
//////////////////////////////
 
// decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
void MD5::decode(uint4 output[], const uint1 input[], size_type len)
{
  for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) |
      (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
}
 
//////////////////////////////
 
// encodes input (uint4) into output (unsigned char). Assumes len is
// a multiple of 4.
void MD5::encode(uint1 output[], const uint4 input[], size_type len)
{
  for (size_type i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = input[i] & 0xff;
    output[j+1] = (input[i] >> 8) & 0xff;
    output[j+2] = (input[i] >> 16) & 0xff;
    output[j+3] = (input[i] >> 24) & 0xff;
  }
}
 
//////////////////////////////
 
// apply MD5 algo on a block
void MD5::transform(const uint1 block[blocksize])
{
  uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
  decode (x, block, blocksize);
 
  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, this->precomputed[0]); /* 1 */
  FF (d, a, b, c, x[ 1], S12, this->precomputed[1]); /* 2 */
  FF (c, d, a, b, x[ 2], S13, this->precomputed[2]); /* 3 */
  FF (b, c, d, a, x[ 3], S14, this->precomputed[3]); /* 4 */
  FF (a, b, c, d, x[ 4], S11, this->precomputed[4]); /* 5 */
  FF (d, a, b, c, x[ 5], S12, this->precomputed[5]); /* 6 */
  FF (c, d, a, b, x[ 6], S13, this->precomputed[6]); /* 7 */
  FF (b, c, d, a, x[ 7], S14, this->precomputed[7]); /* 8 */
  FF (a, b, c, d, x[ 8], S11, this->precomputed[8]); /* 9 */
  FF (d, a, b, c, x[ 9], S12, this->precomputed[9]); /* 10 */
  FF (c, d, a, b, x[10], S13, this->precomputed[10]); /* 11 */
  FF (b, c, d, a, x[11], S14, this->precomputed[11]); /* 12 */
  FF (a, b, c, d, x[12], S11, this->precomputed[12]); /* 13 */
  FF (d, a, b, c, x[13], S12, this->precomputed[13]); /* 14 */
  FF (c, d, a, b, x[14], S13, this->precomputed[14]); /* 15 */
  FF (b, c, d, a, x[15], S14, this->precomputed[15]); /* 16 */
 
  /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, this->precomputed[16]); /* 17 */
  GG (d, a, b, c, x[ 6], S22, this->precomputed[17]); /* 18 */
  GG (c, d, a, b, x[11], S23, this->precomputed[18]); /* 19 */
  GG (b, c, d, a, x[ 0], S24, this->precomputed[19]); /* 20 */
  GG (a, b, c, d, x[ 5], S21, this->precomputed[20]); /* 21 */
  GG (d, a, b, c, x[10], S22,  this->precomputed[21]); /* 22 */
  GG (c, d, a, b, x[15], S23, this->precomputed[22]); /* 23 */
  GG (b, c, d, a, x[ 4], S24, this->precomputed[23]); /* 24 */
  GG (a, b, c, d, x[ 9], S21, this->precomputed[24]); /* 25 */
  GG (d, a, b, c, x[14], S22, this->precomputed[25]); /* 26 */
  GG (c, d, a, b, x[ 3], S23, this->precomputed[26]); /* 27 */
  GG (b, c, d, a, x[ 8], S24, this->precomputed[27]); /* 28 */
  GG (a, b, c, d, x[13], S21, this->precomputed[28]); /* 29 */
  GG (d, a, b, c, x[ 2], S22, this->precomputed[29]); /* 30 */
  GG (c, d, a, b, x[ 7], S23, this->precomputed[30]); /* 31 */
  GG (b, c, d, a, x[12], S24, this->precomputed[31]); /* 32 */
 
  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, this->precomputed[32]); /* 33 */
  HH (d, a, b, c, x[ 8], S32, this->precomputed[33]); /* 34 */
  HH (c, d, a, b, x[11], S33, this->precomputed[34]); /* 35 */
  HH (b, c, d, a, x[14], S34, this->precomputed[35]); /* 36 */
  HH (a, b, c, d, x[ 1], S31, this->precomputed[36]); /* 37 */
  HH (d, a, b, c, x[ 4], S32, this->precomputed[37]); /* 38 */
  HH (c, d, a, b, x[ 7], S33, this->precomputed[38]); /* 39 */
  HH (b, c, d, a, x[10], S34, this->precomputed[39]); /* 40 */
  HH (a, b, c, d, x[13], S31, this->precomputed[40]); /* 41 */
  HH (d, a, b, c, x[ 0], S32, this->precomputed[41]); /* 42 */
  HH (c, d, a, b, x[ 3], S33, this->precomputed[42]); /* 43 */
  HH (b, c, d, a, x[ 6], S34, this->precomputed[43]); /* 44 */
  HH (a, b, c, d, x[ 9], S31, this->precomputed[44]); /* 45 */
  HH (d, a, b, c, x[12], S32, this->precomputed[45]); /* 46 */
  HH (c, d, a, b, x[15], S33, this->precomputed[46]); /* 47 */
  HH (b, c, d, a, x[ 2], S34, this->precomputed[47]); /* 48 */
 
  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, this->precomputed[48]); /* 49 */
  II (d, a, b, c, x[ 7], S42, this->precomputed[49]); /* 50 */
  II (c, d, a, b, x[14], S43, this->precomputed[50]); /* 51 */
  II (b, c, d, a, x[ 5], S44, this->precomputed[51]); /* 52 */
  II (a, b, c, d, x[12], S41, this->precomputed[52]); /* 53 */
  II (d, a, b, c, x[ 3], S42, this->precomputed[53]); /* 54 */
  II (c, d, a, b, x[10], S43, this->precomputed[54]); /* 55 */
  II (b, c, d, a, x[ 1], S44, this->precomputed[55]); /* 56 */
  II (a, b, c, d, x[ 8], S41, this->precomputed[56]); /* 57 */
  II (d, a, b, c, x[15], S42, this->precomputed[57]); /* 58 */
  II (c, d, a, b, x[ 6], S43, this->precomputed[58]); /* 59 */
  II (b, c, d, a, x[13], S44, this->precomputed[59]); /* 60 */
  II (a, b, c, d, x[ 4], S41, this->precomputed[60]); /* 61 */
  II (d, a, b, c, x[11], S42, this->precomputed[61]); /* 62 */
  II (c, d, a, b, x[ 2], S43, this->precomputed[62]); /* 63 */
  II (b, c, d, a, x[ 9], S44, this->precomputed[63]); /* 64 */
 
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
 
  // Zeroize sensitive information.
  memset(x, 0, sizeof x);
}
 
//////////////////////////////
 
// MD5 block update operation. Continues an MD5 message-digest
// operation, processing another message block
void MD5::update(const unsigned char input[], size_type length)
{
  // compute number of bytes mod 64
  size_type index = count[0] / 8 % blocksize;
 
  // Update number of bits
  if ((count[0] += (length << 3)) < (length << 3))
    count[1]++;
  count[1] += (length >> 29);
 
  // number of bytes we need to fill in buffer
  size_type firstpart = 64 - index;
 
  size_type i;
 
  // transform as many times as possible.
  if (length >= firstpart)
  {
    // fill buffer first, transform
    memcpy(&buffer[index], input, firstpart);
    transform(buffer);
 
    // transform chunks of blocksize (64 bytes)
    for (i = firstpart; i + blocksize <= length; i += blocksize)
      transform(&input[i]);
 
    index = 0;
  }
  else
    i = 0;
 
  // buffer remaining input
  memcpy(&buffer[index], &input[i], length-i);
}
 
//////////////////////////////
 
// for convenience provide a verson with signed char
void MD5::update(const char input[], size_type length)
{
  update((const unsigned char*)input, length);
}
 
//////////////////////////////
 
// MD5 finalization. Ends an MD5 message-digest operation, writing the
// the message digest and zeroizing the context.
MD5& MD5::finalize()
{
  static unsigned char padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
 
  if (!finalized) {
    // Save number of bits
    unsigned char bits[8];
    encode(bits, count, 8);
 
    // pad out to 56 mod 64.
    size_type index = count[0] / 8 % 64;
    size_type padLen = (index < 56) ? (56 - index) : (120 - index);
    update(padding, padLen);
 
    // Append length (before padding)
    update(bits, 8);
 
    // Store state in digest
    encode(digest, state, 16);
 
    // Zeroize sensitive information.
    memset(buffer, 0, sizeof buffer);
    memset(count, 0, sizeof count);
 
    finalized=true;
  }
 
  return *this;
}
 
//////////////////////////////
 
// return hex representation of digest as string
std::string MD5::hexdigest() const
{
  if (!finalized)
    return "";
 
  char buf[33];
  for (int i=0; i<16; i++)
    sprintf(buf+i*2, "%02x", digest[i]);
  buf[32]=0;
 
  return std::string(buf);
}
 
//////////////////////////////
 
std::ostream& operator<<(std::ostream& out, MD5 md5)
{
  return out << md5.hexdigest();
}
 
//////////////////////////////
 
std::string md5(const std::string str, unsigned int precomputed[64], unsigned int state[4])
{
    MD5 md5 = MD5(str, precomputed, state);
 
    return md5.hexdigest();
}