/*
 * Copyright 2010-2013 Maarten Baert
 * maarten-baert@hotmail.com
 * http://www.maartenbaert.be/
 * 
 * This file is part of Http Dll 2.
 * 
 * Http Dll 2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Http Dll 2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Http Dll 2. If not, see <http://www.gnu.org/licenses/>.
 */

#include "Hash.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

inline uint32_t roll_left(uint32_t x, unsigned int n) {
	return (x << n) | (x >> (32 - n));
}
inline uint32_t reverse_endianness_32(uint32_t a) {
	return (a >> 24) | (a << 24) | ((a & 0xff00) << 8) | ((a & 0xff0000) >> 8);
}

inline void md5_ff(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, unsigned int s, uint32_t t) {
	a += ((b & c) | ((~b) & d)) + x + t;
	a = roll_left(a, s) + b;
}
inline void md5_gg(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, unsigned int s, uint32_t t) {
	a += ((b & d) | (c & (~d))) + x + t;
	a = roll_left(a, s) + b;
}
inline void md5_hh(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, unsigned int s, uint32_t t) {
	a += (b ^ c ^ d) + x + t;
	a = roll_left(a, s) + b;
}
inline void md5_ii(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, unsigned int s, uint32_t t) {
	a += (c ^ (b | (~d))) + x + t;
	a = roll_left(a, s) + b;
}

// initialize a md5 hash
void md5_init(uint32_t result[4]) {
	result[0] = 0x67452301;
	result[1] = 0xefcdab89;
	result[2] = 0x98badcfe;
	result[3] = 0x10325476;
}

// add 16 words to the md5 hash
void md5_hash(uint32_t result[4], uint32_t block[16]) {
	
	uint32_t a = result[0];
	uint32_t b = result[1];
	uint32_t c = result[2];
	uint32_t d = result[3];
	
	md5_ff(a, b, c, d, block[ 0],  7, 0xd76aa478);
	md5_ff(d, a, b, c, block[ 1], 12, 0xe8c7b756);
	md5_ff(c, d, a, b, block[ 2], 17, 0x242070db);
	md5_ff(b, c, d, a, block[ 3], 22, 0xc1bdceee);
	md5_ff(a, b, c, d, block[ 4],  7, 0xf57c0faf);
	md5_ff(d, a, b, c, block[ 5], 12, 0x4787c62a);
	md5_ff(c, d, a, b, block[ 6], 17, 0xa8304613);
	md5_ff(b, c, d, a, block[ 7], 22, 0xfd469501);
	md5_ff(a, b, c, d, block[ 8],  7, 0x698098d8);
	md5_ff(d, a, b, c, block[ 9], 12, 0x8b44f7af);
	md5_ff(c, d, a, b, block[10], 17, 0xffff5bb1);
	md5_ff(b, c, d, a, block[11], 22, 0x895cd7be);
	md5_ff(a, b, c, d, block[12],  7, 0x6b901122);
	md5_ff(d, a, b, c, block[13], 12, 0xfd987193);
	md5_ff(c, d, a, b, block[14], 17, 0xa679438e);
	md5_ff(b, c, d, a, block[15], 22, 0x49b40821);
	
	md5_gg(a, b, c, d, block[ 1],  5, 0xf61e2562);
	md5_gg(d, a, b, c, block[ 6],  9, 0xc040b340);
	md5_gg(c, d, a, b, block[11], 14, 0x265e5a51);
	md5_gg(b, c, d, a, block[ 0], 20, 0xe9b6c7aa);
	md5_gg(a, b, c, d, block[ 5],  5, 0xd62f105d);
	md5_gg(d, a, b, c, block[10],  9, 0x02441453);
	md5_gg(c, d, a, b, block[15], 14, 0xd8a1e681);
	md5_gg(b, c, d, a, block[ 4], 20, 0xe7d3fbc8);
	md5_gg(a, b, c, d, block[ 9],  5, 0x21e1cde6);
	md5_gg(d, a, b, c, block[14],  9, 0xc33707d6);
	md5_gg(c, d, a, b, block[ 3], 14, 0xf4d50d87);
	md5_gg(b, c, d, a, block[ 8], 20, 0x455a14ed);
	md5_gg(a, b, c, d, block[13],  5, 0xa9e3e905);
	md5_gg(d, a, b, c, block[ 2],  9, 0xfcefa3f8);
	md5_gg(c, d, a, b, block[ 7], 14, 0x676f02d9);
	md5_gg(b, c, d, a, block[12], 20, 0x8d2a4c8a);
	
	md5_hh(a, b, c, d, block[ 5],  4, 0xfffa3942);
	md5_hh(d, a, b, c, block[ 8], 11, 0x8771f681);
	md5_hh(c, d, a, b, block[11], 16, 0x6d9d6122);
	md5_hh(b, c, d, a, block[14], 23, 0xfde5380c);
	md5_hh(a, b, c, d, block[ 1],  4, 0xa4beea44);
	md5_hh(d, a, b, c, block[ 4], 11, 0x4bdecfa9);
	md5_hh(c, d, a, b, block[ 7], 16, 0xf6bb4b60);
	md5_hh(b, c, d, a, block[10], 23, 0xbebfbc70);
	md5_hh(a, b, c, d, block[13],  4, 0x289b7ec6);
	md5_hh(d, a, b, c, block[ 0], 11, 0xeaa127fa);
	md5_hh(c, d, a, b, block[ 3], 16, 0xd4ef3085);
	md5_hh(b, c, d, a, block[ 6], 23, 0x04881d05);
	md5_hh(a, b, c, d, block[ 9],  4, 0xd9d4d039);
	md5_hh(d, a, b, c, block[12], 11, 0xe6db99e5);
	md5_hh(c, d, a, b, block[15], 16, 0x1fa27cf8);
	md5_hh(b, c, d, a, block[ 2], 23, 0xc4ac5665);
	
	md5_ii(a, b, c, d, block[ 0],  6, 0xf4292244);
	md5_ii(d, a, b, c, block[ 7], 10, 0x432aff97);
	md5_ii(c, d, a, b, block[14], 15, 0xab9423a7);
	md5_ii(b, c, d, a, block[ 5], 21, 0xfc93a039);
	md5_ii(a, b, c, d, block[12],  6, 0x655b59c3);
	md5_ii(d, a, b, c, block[ 3], 10, 0x8f0ccc92);
	md5_ii(c, d, a, b, block[10], 15, 0xffeff47d);
	md5_ii(b, c, d, a, block[ 1], 21, 0x85845dd1);
	md5_ii(a, b, c, d, block[ 8],  6, 0x6fa87e4f);
	md5_ii(d, a, b, c, block[15], 10, 0xfe2ce6e0);
	md5_ii(c, d, a, b, block[ 6], 15, 0xa3014314);
	md5_ii(b, c, d, a, block[13], 21, 0x4e0811a1);
	md5_ii(a, b, c, d, block[ 4],  6, 0xf7537e82);
	md5_ii(d, a, b, c, block[11], 10, 0xbd3af235);
	md5_ii(c, d, a, b, block[ 2], 15, 0x2ad7d2bb);
	md5_ii(b, c, d, a, block[ 9], 21, 0xeb86d391);
	
	result[0] += a;
	result[1] += b;
	result[2] += c;
	result[3] += d;
	
}

void MD5::Begin() {
	blocks = 0;
	used = 0;
	md5_init(result.w);
}

bool MD5::ReadFile(const char* fname) {
	FILE* f;
	f = fopen(fname, "rb");
	if(f == NULL) return false;
	for( ; ; ) {
		used += fread(block.x + used, 1, 64 - used, f);
		if(used < 64) break;
		md5_hash(result.w, block.w);
		++blocks;
		used = 0;
	}
	fclose(f);
	return true;
}

void MD5::ReadMem(const void* data, unsigned int datalen) {
	if(datalen == 0) return;
	unsigned int j = 0;
	uint8_t* in = (uint8_t*)(data);
	while(datalen - j >= 64 - used) {
		memcpy(block.x + used, in + j, 64 - used);
		j += 64 - used;
		md5_hash(result.w, block.w);
		++blocks;
		used = 0;
	}
	if(datalen - j > 0) {
		memcpy(block.x + used, in + j, datalen - j);
		used += datalen - j;
	}
}

void MD5::End() {
	block.x[used] = 0x80;
	if(64 - used < 8 + 1) {
		memset(block.x + used + 1, 0, 64 - used - 1);
		md5_hash(result.w, block.w);
		memset(block.x, 0, 64 - 8);
	} else {
		memset(block.x + used + 1, 0, 64 - used - 1 - 8);
	}
	block.w[14] = (blocks << 9) | (used << 3);
	block.w[15] = blocks >> (32 - 9);
	md5_hash(result.w, block.w);
	memset(block.x, 0, 64);
}

// initialize a sha1 hash
void sha1_init(uint32_t result[5]) {
	result[0] = 0x67452301;
	result[1] = 0xefcdab89;
	result[2] = 0x98badcfe;
	result[3] = 0x10325476;
	result[4] = 0xc3d2e1f0;
}

// add 16 words to the sha1 hash
void sha1_hash(uint32_t result[5], uint32_t block[16]) {
	
	uint32_t w[80];
	for(unsigned int t = 0; t < 16; ++t) {
		w[t] = reverse_endianness_32(block[t]);
	}
	for(unsigned int t = 16; t < 80; ++t) {
		w[t] = roll_left(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
	}
	
	uint32_t a = result[0];
	uint32_t b = result[1];
	uint32_t c = result[2];
	uint32_t d = result[3];
	uint32_t e = result[4];
	
	for(unsigned int t = 0; t < 20; ++t) {
		uint32_t temp = roll_left(a, 5) + ((b & c) | ((~b) & d)) + e + w[t] + 0x5a827999;
		e = d;
		d = c;
		c = roll_left(b, 30);
		b = a;
		a = temp;
	}
	for(unsigned int t = 20; t < 40; t++) {
		uint32_t temp = roll_left(a, 5) + (b ^ c ^ d) + e + w[t] + 0x6ed9eba1;
		e = d;
		d = c;
		c = roll_left(b, 30);
		b = a;
		a = temp;
	}
	for(unsigned int t = 40; t < 60; t++) {
		uint32_t temp = roll_left(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[t] + 0x8f1bbcdc;
		e = d;
		d = c;
		c = roll_left(b, 30);
		b = a;
		a = temp;
	}
	for(unsigned int t = 60; t < 80; t++) {
		uint32_t temp = roll_left(a, 5) + (b ^ c ^ d) + e + w[t] + 0xca62c1d6;
		e = d;
		d = c;
		c = roll_left(b, 30);
		b = a;
		a = temp;
	}
	
	result[0] += a;
	result[1] += b;
	result[2] += c;
	result[3] += d;
	result[4] += e;
	
}

void SHA1::Begin() {
	blocks = 0;
	used = 0;
	sha1_init(result.w);
}

bool SHA1::ReadFile(const char* fname) {
	FILE* f;
	f = fopen(fname, "rb");
	if(f == NULL) return false;
	for( ; ; ) {
		used += fread(block.x + used, 1, 64 - used, f);
		if(used < 64) break;
		sha1_hash(result.w, block.w);
		++blocks;
		used = 0;
	}
	fclose(f);
	return true;
}

void SHA1::ReadMem(const void* data, unsigned int datalen) {
	if(datalen == 0) return;
	unsigned int j = 0;
	uint8_t* in = (uint8_t*)(data);
	while(datalen - j >= 64 - used) {
		memcpy(block.x + used, in + j, 64 - used);
		j += 64 - used;
		sha1_hash(result.w, block.w);
		++blocks;
		used = 0;
	}
	if(datalen - j > 0) {
		memcpy(block.x + used, in + j, datalen - j);
		used += datalen - j;
	}
}

void SHA1::End() {
	block.x[used] = 0x80;
	if(64 - used < 8 + 1) {
		memset(block.x + used + 1, 0, 64 - used - 1);
		sha1_hash(result.w, block.w);
		memset(block.x, 0, 64 - 8);
	} else {
		memset(block.x + used + 1, 0, 64 - used - 1 - 8);
	}
	block.w[14] = reverse_endianness_32(blocks >> (32 - 9));
	block.w[15] = reverse_endianness_32((blocks << 9) | (used << 3));
	sha1_hash(result.w, block.w);
	memset(block.x, 0, 64);
	result.w[0] = reverse_endianness_32(result.w[0]);
	result.w[1] = reverse_endianness_32(result.w[1]);
	result.w[2] = reverse_endianness_32(result.w[2]);
	result.w[3] = reverse_endianness_32(result.w[3]);
	result.w[4] = reverse_endianness_32(result.w[4]);
}

/*-
 *  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 */

const uint32_t crc_32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

void crc32_hash(uint32_t *result, uint8_t octet) {
	*result = crc_32_tab[(*result ^ octet) & 0xFF] ^ (*result >> 8);
}

void CRC32::Begin() {
	result.w = 0xFFFFFFFF;
}

bool SHA1::ReadFile(const char* fname) {
	FILE* f;
	f = fopen(fname, "rb");
	if(f == NULL) return false;

	uint8_t block[64];
	for( ; ; ) {
		size_t len = fread(block, 1, 64, f);
		if (len == 0)
			break;
		for (unsigned int i = 0; i < len; ++i)
			crc32_hash(result.w, block[i]);
	}
	fclose(f);
	return true;
}

void CRC32::ReadMem(const void* data, unsigned int datalen) {
	uint8_t* in = (uint8_t*)(data);
	while (datalen--)
		crc32_hash(&result.w, *in++);
}

void CRC32::End() {
	result.w ^= 0xFFFFFFFF;
	result.w = reverse_endianness_32(result.w);
}