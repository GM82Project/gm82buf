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

#include "gm.h"
#include "StringConversion.h"

MD5 gm_md5;
SHA1 gm_sha1;
CRC32 gm_crc32;

gmexport const char* md5_file(const char* filename) {
    ///md5_file(filename)
    //filename: file to hash
    //Returns the MD5 hash of the file contents.
    
    gm_md5.Begin();
    gm_md5.ReadFile(filename);
    gm_md5.End();
    gmreturnstring = BinToHex(gm_md5.Result(), 16);
    return gmreturnstring.c_str();
}

gmexport const char* md5_string(const char* string) {
    ///md5_string(string)
    //string: string to hash
    //Returns the MD5 hash of the string.
    
    gm_md5.Begin();
    gm_md5.ReadMem(string, strlen(string));
    gm_md5.End();
    gmreturnstring = BinToHex(gm_md5.Result(), 16);
    return gmreturnstring.c_str();
}

gmexport const char* md5_buffer(double id) {
    ///md5_buffer(buffer)
    //buffer: buffer to hash
    //Returns the MD5 hash of the buffer contents.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    gm_md5.Begin();
    gm_md5.ReadMem(b->GetData(), b->GetLength());
    gm_md5.End();
    gmreturnstring = BinToHex(gm_md5.Result(), 16);
    return gmreturnstring.c_str();
}

gmexport const char* md5_buffer_part(double id, double pos, double len) {
    ///md5_buffer_part(buffer,pos,len)
    //buffer: buffer to hash
    //pos,len: part of buffer to hash
    //Returns the MD5 hash of part of the buffer contents.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    gm_md5.Begin();
    unsigned int l = b->GetLength();
    unsigned int _pos = gm_cast<unsigned int>(pos);
    unsigned int _len = gm_cast<unsigned int>(len);
    if(_pos > l) _pos = l;
    if(_len > l - _pos) _len = l - _pos;
    gm_md5.ReadMem(b->GetData() + _pos, _len);
    gm_md5.End();
    gmreturnstring = BinToHex(gm_md5.Result(), 16);
    return gmreturnstring.c_str();
}


gmexport const char* sha1_file(const char* filename) {
    ///sha1_file(filename)
    //filename: file to hash
    //Returns the SHA1 hash of the file contents.
    
    gm_sha1.Begin();
    gm_sha1.ReadFile(filename);
    gm_sha1.End();
    gmreturnstring = BinToHex(gm_sha1.Result(), 20);
    return gmreturnstring.c_str();
}

gmexport const char* sha1_string(const char* string) {
    ///sha1_string(string)
    //string: string to hash
    //Returns the SHA1 hash of the string.
    
    gm_sha1.Begin();
    gm_sha1.ReadMem(string, strlen(string));
    gm_sha1.End();
    gmreturnstring = BinToHex(gm_sha1.Result(), 20);
    return gmreturnstring.c_str();
}

gmexport const char* sha1_buffer(double id) {
    ///sha1_buffer(buffer)
    //buffer: buffer to hash
    //Returns the SHA1 hash of the buffer contents.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    gm_sha1.Begin();
    gm_sha1.ReadMem(b->GetData(), b->GetLength());
    gm_sha1.End();
    gmreturnstring = BinToHex(gm_sha1.Result(), 20);
    return gmreturnstring.c_str();
}

gmexport const char* sha1_buffer_part(double id, double pos, double len) {
    ///sha1_buffer_part(buffer,pos,len)
    //buffer: buffer to hash
    //pos,len: part of buffer to hash
    //Returns the SHA1 hash of part of the buffer contents.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    gm_sha1.Begin();
    unsigned int l = b->GetLength();
    unsigned int _pos = gm_cast<unsigned int>(pos);
    unsigned int _len = gm_cast<unsigned int>(len);
    if(_pos > l) _pos = l;
    if(_len > l - _pos) _len = l - _pos;
    gm_sha1.ReadMem(b->GetData() + _pos, _len);
    gm_sha1.End();
    gmreturnstring = BinToHex(gm_sha1.Result(), 20);
    return gmreturnstring.c_str();
}

gmexport const char* crc32_file(const char* filename) {
    ///crc32_file(filename)
    //filename: file to hash
    //Returns the CRC32 hash of the file contents.
    
    gm_crc32.Begin();
    gm_crc32.ReadFile(filename);
    gm_crc32.End();
    gmreturnstring = BinToHex(gm_crc32.Result(), 4);
    return gmreturnstring.c_str();
}

gmexport const char* crc32_string(const char* string) {
    ///crc32_string(string)
    //string: string to hash
    //Returns the CRC32 hash of the string.
    
    gm_crc32.Begin();
    gm_crc32.ReadMem(string, strlen(string));
    gm_crc32.End();
    gmreturnstring = BinToHex(gm_crc32.Result(), 4);
    return gmreturnstring.c_str();
}

gmexport const char* crc32_buffer(double id) {
    ///crc32_buffer(buffer)
    //buffer: buffer to hash
    //Returns the CRC32 hash of the buffer contents.
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    gm_crc32.Begin();
    gm_crc32.ReadMem(b->GetData(), b->GetLength());
    gm_crc32.End();
    gmreturnstring = BinToHex(gm_crc32.Result(), 4);
    return gmreturnstring.c_str();
}

gmexport const char* crc32_buffer_part(double id, double pos, double len) {
    ///crc32_buffer_part(buffer,pos,len)
    //buffer: buffer to hash
    //pos,len: part of buffer to hash
    //Returns the CRC32 hash of part of the buffer contents.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    gm_crc32.Begin();
    unsigned int l = b->GetLength();
    unsigned int _pos = gm_cast<unsigned int>(pos);
    unsigned int _len = gm_cast<unsigned int>(len);
    if(_pos > l) _pos = l;
    if(_len > l - _pos) _len = l - _pos;
    gm_crc32.ReadMem(b->GetData() + _pos, _len);
    gm_crc32.End();
    gmreturnstring = BinToHex(gm_crc32.Result(), 4);
    return gmreturnstring.c_str();
}
