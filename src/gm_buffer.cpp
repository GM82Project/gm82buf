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

gmexport double __gm82buf_buffer_create() {
    Buffer *b = NULL;
    b = new Buffer();
    try {
        gmdata.buffers.insert(std::pair<unsigned int, Buffer*>(++gmdata.idcounter_buffers, b));
    }
    catch(...) {
        delete b;
        throw;
    }
    return gmdata.idcounter_buffers;
}

gmexport double buffer_destroy(double id) {
    ///buffer_destroy(id)
    //id: buffer index
    //Destroys a buffer.
    //Always destroy buffers when you're done with them to free up memory.
    
    std::map<unsigned int, Buffer*>::iterator it = gmdata.buffers.find(gm_cast<unsigned int>(id));
    if(it == gmdata.buffers.end()) {
        return 0;
    }
    delete it->second;
    gmdata.buffers.erase(it);
    return 1;
}

gmexport double buffer_exists(double id) {
    ///buffer_exists(id)
    //id: buffer index
    //Returns whether the buffer with 'id' exists.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    return (b == NULL)? 0 : 1;
}

/*
gmexport const char* buffer_to_string(double id) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return b->ToString();
}
*/

gmexport double buffer_get_pos(double id) {
    ///buffer_get_pos(id)
    //id: buffer index
    //Returns the current caret position in the buffer.
    //The caret position is used for reading and writing to the buffer.
    //Buffers are automatically expanded when the write operation exceeds the current buffer length.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return b->GetPos();
}

gmexport double buffer_get_length(double id) {
    ///buffer_get_length(id)
    //id: buffer index
    //Returns the current size of the buffer in bytes.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return b->GetLength();
}

gmexport double buffer_at_end(double id) {
    ///buffer_at_end(id)
    //id: buffer index
    //Returns whether the buffer caret is currently at the very end of the buffer.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return (b->IsAtEnd())? 1 : 0;
}

gmexport double buffer_get_error(double id) {
    ///buffer_get_error(id)
    //id: buffer index
    //returns: whether the buffer has been locked with an error
    //Errors are usually caused by reading out of bounds.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return (b->GetError())? 1 : 0;
}

gmexport double buffer_clear_error(double id) {
    ///buffer_clear_error(id)
    //id: buffer index
    //Clears the error state of a buffer, allowing it to be used again.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->ClearError();
    return 1;
}

gmexport double buffer_clear(double id) {
    ///buffer_clear(id)
    //id: buffer index
    //Clears the buffer of all data and sets the caret at the start.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->Clear();
    return 1;
}

gmexport double buffer_set_pos(double id, double pos) {
    ///buffer_set_pos(id,pos)
    //id: buffer index
    //pos: position to set
    //Sets the buffer caret to the specified position for reading and writing.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->SetPos(gm_cast<unsigned int>(pos));
    return 1;
}

gmexport double buffer_set_size(double id, double len) {
    ///buffer_set_size(id,size)
    //id: buffer index
    //size: new size
    //Resizes the buffer to have a specific size.
    //Buffers automatically expand as they're written to, but this can be used to preallocate memory for a large operation.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->SetLength(gm_cast<unsigned int>(len));
    return 1;
}

gmexport double buffer_read_from_file(double id, const char* filename) {
    ///buffer_load(id,filename)
    //id: buffer index
    //filename: file to load from
    //returns: buffer id
    //Loads the entire file into the buffer, resizing it to fit. Sets the caret to the start.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) {
        return 0;
    }
    return (b->ReadFromFile(filename))?1:0;
}

gmexport double buffer_read_from_file_part(double id, const char* filename, double pos, double len) {
    ///buffer_load_part(id,filename,pos,len)
    //id: buffer index
    //filename: file to load from
    //pos/len: part of the file to load
    //returns: whether the read was successful
    //Loads part of a file into a buffer, resizing it to fit. Sets the caret to the start.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) {
        return 0;
    }
    return (b->ReadFromFilePart(filename, gm_cast<unsigned int>(pos), gm_cast<unsigned int>(len)))?1:0;
}

gmexport double buffer_write_to_file(double id, const char* filename) {
    ///buffer_save(id,filename)
    //id: buffer index
    //filename: file to save to
    //Saves the buffer to disk.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return (b->WriteToFile(filename,false))? 1 : 0;
}
gmexport double buffer_write_to_temp_file(double id, const char* filename) {
    ///buffer_save(id,filename)
    //id: buffer index
    //filename: file to save to
    //Saves the buffer to a temporary file.
    //Windows attempts to keep such temporary files in cache only, which makes them faster to handle.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return (b->WriteToFile(filename,true))? 1 : 0;
}

gmexport double buffer_append_to_file(double id, const char* filename) {
    ///buffer_save_append(id,filename)
    //id: buffer index
    //filename: file to save to
    //Saves the buffer to disk, appending to the existing file.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return (b->AppendToFile(filename))? 1 : 0;
}

gmexport double buffer_rc4_crypt(double id, const char* key) {
    ///buffer_rc4(id,key)
    //id: buffer index
    //key: password to use
    //Scrambles a buffer using a rotating cypher. Apply the same password again to unscramble.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->RC4Crypt(key, strlen(key));
    return 1;
}

gmexport double buffer_rc4_crypt_buffer(double id, double id2) {
    ///buffer_rc4_buffer(id,idkey)
    //id: buffer index
    //idkey: buffer to use as password
    //Scrambles a buffer using a rotating cypher. Apply the same password again to unscramble.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    Buffer *b2 = gmdata.FindBuffer(gm_cast<unsigned int>(id2));
    if(b2 == NULL) return 0;
    b->RC4Crypt(b2->GetData(), b2->GetLength());
    return 1;
}

gmexport double buffer_zlib_compress(double id) {
    ///buffer_deflate(id)
    //id: buffer index
    //Compresses a buffer using zlib.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->ZLibCompress();
    return 1;
}

gmexport double buffer_zlib_uncompress(double id) {
    ///buffer_inflate(id)
    //id: buffer index
    //Decompresses a buffer using zlib.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return (b->ZLibUncompress())? 1 : 0;
}

template<typename T>
static double buffer_read_type(double id) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if (b == NULL) return 0.0;

    return (double)b->ReadType<T>();
}

gmexport double buffer_read_int8(double id) {
    ///buffer_read_i8(id)
    //id: buffer index
    //returns: value
    //Reads a signed char (-128 to 127, one byte).
    
    return buffer_read_type<int8_t>(id);
}

gmexport double buffer_read_uint8(double id) {
    ///buffer_read_u8(id)
    //id: buffer index
    //returns: value
    //Reads an unsigned byte (0 to 255, one byte).
    
    return buffer_read_type<uint8_t>(id);
}

gmexport double buffer_read_int16(double id) {
    ///buffer_read_i16(id)
    //id: buffer index
    //returns: value
    //Reads a signed short (-32768 to 32767, two bytes).
    
    return buffer_read_type<int16_t>(id);
}

gmexport double buffer_read_uint16(double id) {
    ///buffer_read_u16(id)
    //id: buffer index
    //returns: value
    //Reads an unsigned short (0 to 65535, two bytes).
    
    return buffer_read_type<uint16_t>(id);
}

gmexport double buffer_read_int32(double id) {
    ///buffer_read_i32(id)
    //id: buffer index
    //returns: value
    //Reads a signed long (-2147483648 to 2147483647, four bytes).
    
    return buffer_read_type<int32_t>(id);
}

gmexport double buffer_read_uint32(double id) {
    ///buffer_read_u32(id)
    //id: buffer index
    //returns: value
    //Reads an unsigned long (0 to 4294967295, four bytes).
    
    return buffer_read_type<uint32_t>(id);
}

gmexport double buffer_read_int64(double id) {
    ///buffer_read_i64(id)
    //id: buffer index
    //returns: value
    //Reads a signed long long (-9223372036854775808 to 9223372036854775807, eight bytes).
    //Note that integers above 2^53 (9007199254740992) cannot accurately be represented in a double,
    //and as such, may lose precision when handled in GML.
    
    return buffer_read_type<int64_t>(id);
}

gmexport double buffer_read_uint64(double id) {
    ///buffer_read_u32(id)
    //id: buffer index
    //returns: value
    //Reads an unsigned long long (0 to 18446744073709551615, eight bytes).
    //Note that integers above 2^53 (9007199254740992) cannot accurately be represented in a double,
    //and as such, may lose precision when handled in GML.    
    
    return buffer_read_type<uint64_t>(id);
}

/*
gmexport double buffer_read_intv(double id) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return b->ReadIntV();
}

gmexport double buffer_read_uintv(double id) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    return b->ReadUIntV();
}
*/

gmexport double buffer_read_float32(double id) {
    ///buffer_read_float(id)
    //id: buffer index
    //returns: value
    //Reads a float (24 bits of precision, four bytes).
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    float data=b->ReadType<float>();
    if (isnan(data) || isinf(data)) return 0;
    return data;
}

gmexport double buffer_read_float64(double id) {
    ///buffer_read_double(id)
    //id: buffer index
    //returns: value
    //Reads a double (53 bits of precision, eight bytes).
    //This is the most accurate way to store GML Real numbers in a buffer.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    double data=b->ReadType<double>();
    if (isnan(data) || isinf(data)) return 0;
    return data;
}

template<typename T, size_t N>
static double buffer_write_num_types(double id, const double (&vals)[N]) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if (b == NULL) return 0.0;

    for (size_t i = 0; i < N; ++i)
        b->WriteType<T>(gm_cast<T>(vals[i]));

    return 1.0;
}

template<typename T>
static double buffer_write_type(double id, double value) {
    return buffer_write_num_types<T>(id, {value});
}

gmexport double buffer_write_int8(double id, double value) {
    ///buffer_write_i8(id,value)
    //id: buffer index
    //value: value to write
    //Writes a signed char (-128 to 127, one byte).
    
    return buffer_write_type<int8_t>(id, value);
}

gmexport double buffer_write_uint8(double id, double value) {
    ///buffer_write_u8(id,value)
    //id: buffer index
    //value: value to write
    //Writes an unsigned byte (0 to 255, one byte).
    
    return buffer_write_type<uint8_t>(id, value);
}

gmexport double buffer_write_int16(double id, double value) {
    ///buffer_write_i16(id,value)
    //id: buffer index
    //value: value to write
    //Writes a signed short (-32768 to 32767, two bytes).
    
    return buffer_write_type<int16_t>(id, value);
}

gmexport double buffer_write_uint16(double id, double value) {
    ///buffer_write_u16(id,value)
    //id: buffer index
    //value: value to write
    //Writes an unsigned short (0 to 65535, two bytes).
    
    return buffer_write_type<uint16_t>(id, value);
}

gmexport double buffer_write_int32(double id, double value) {
    ///buffer_write_i32(id,value)
    //id: buffer index
    //value: value to write
    //Writes a signed long (-2147483648 to 2147483647, four bytes).
    
    return buffer_write_type<int32_t>(id, value);
}

gmexport double buffer_write_uint32(double id, double value) {
    ///buffer_write_u32(id,value)
    //id: buffer index
    //value: value to write
    //Writes an unsigned long (0 to 4294967295, four bytes).
    
    return buffer_write_type<uint32_t>(id, value);
}

gmexport double buffer_write_int64(double id, double value) {
    ///buffer_write_i64(id,value)
    //id: buffer index
    //value: value to write
    //Writes a signed long long (-9223372036854775808 to 9223372036854775807, eight bytes).
    //Note that integers above 2^53 (9007199254740992) cannot accurately be represented in a double,
    //and as such, may lose precision when handled in GML.
    
    return buffer_write_type<int64_t>(id, value);
}

gmexport double buffer_write_uint64(double id, double value) {
    ///buffer_write_u32(id,value)
    //id: buffer index
    //value: value to write
    //Writes an unsigned long long (0 to 18446744073709551615, eight bytes).
    //Note that integers above 2^53 (9007199254740992) cannot accurately be represented in a double,
    //and as such, may lose precision when handled in GML.    
    
    return buffer_write_type<uint64_t>(id, value);
}

/*
gmexport double buffer_write_intv(double id, double value) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->WriteIntV(gm_cast<int32_t>(value));
    return 1;
}

gmexport double buffer_write_uintv(double id, double value) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->WriteUIntV(gm_cast<uint32_t>(value));
    return 1;
}
*/

gmexport double buffer_write_float32(double id, double value) {
    ///buffer_write_double(id,value)
    //id: buffer index
    //value: value to write
    //Writes a float (24 bits of precision, four bytes).
    
    return buffer_write_type<float>(id, value);
}

gmexport double buffer_write_float32x2(double id, double val1, double val2) {
    ///buffer_write_float2(id,val1,val2)
    //id: buffer index
    //val1,2: values to write
    //Writes two floats (24 bits of precision, four bytes) to the buffer.
    //Designed for use with vertex buffers.
    
    return buffer_write_num_types<float>(id, {val1, val2});
}
gmexport double buffer_write_float32x3(double id, double val1, double val2, double val3) {
    ///buffer_write_float3(id,val1,val2,val3)
    //id: buffer index
    //val1,2,3: values to write
    //Writes three floats (24 bits of precision, four bytes) to the buffer.
    //Designed for use with vertex buffers.
    
    return buffer_write_num_types<float>(id, {val1, val2, val3});
}

gmexport double buffer_write_float32x4(double id, double val1, double val2, double val3, double val4) {
    ///buffer_write_float4(id,val1,val2,val3,val4)
    //id: buffer index
    //val1,2,3,4: values to write
    //Writes four floats (24 bits of precision, four bytes) to the buffer.
    //Designed for use with vertex buffers.
    
    return buffer_write_num_types<float>(id, {val1, val2, val3, val4});
}
gmexport double buffer_write_float32x12(double id, double val1, double val2, double val3, double val4, double val5, double val6, double val7, double val8, double val9, double val10, double val11, double val12) {
    ///buffer_write_float12(id,val1,val2,val3,val4)
    //id: buffer index
    //val1,2,3,etc: values to write
    //Writes twelve floats (24 bits of precision, four bytes) to the buffer.
    //Designed for use with vertex buffers.
    
    return buffer_write_num_types<float>(id, {val1, val2, val3, val4, val5, val6, val7, val8, val9, val10, val11, val12});
}

gmexport double buffer_write_float64(double id, double value) {
    ///buffer_write_float(id,value)
    //id: buffer index
    //value: value to write
    //Writes a double (53 bits of precision, eight bytes).
    //This is the most accurate way to store GML Real numbers in a buffer.
    
    return buffer_write_type<double>(id, value);
}

gmexport const char* buffer_read_string(double id) {
    ///buffer_read_string(id)
    //id: buffer index
    //returns: string
    //Reads a null-terminated string from the buffer.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return "";
    gmreturnstring = b->ReadString();
    return gmreturnstring.c_str();
}

gmexport double buffer_write_string(double id, const char* string) {
    ///buffer_write_string(id,string)
    //id: buffer index
    //string: string to write
    //Writes a null-terminated string to the buffer.
    //If your string contains null characters, it is advisable to instead write its length first and then use buffer_read/write_data().
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->WriteString(string);
    return 1;
}

gmexport const char* buffer_read_data(double id, double len) {
    ///buffer_read_data(id,len)
    //id: buffer index
    //len: length in bytes
    //returns: string
    //Reads an amount of arbitrary character data as a string from the buffer.
    //This will read non-printing characters correctly.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return "";
    unsigned int l = gm_cast<unsigned int>(len);
    gmreturnstring = b->ReadData(l);
    return gmreturnstring.c_str();
}

gmexport double buffer_write_data(double id, const char* string) {
    ///buffer_write_data(id,string)
    //id: buffer index
    //string: string to write
    //Writes a string as arbitrary character data to the buffer.
    //This can be used to store non-printing characters correctly.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->WriteDataGML(string, strlen(string));
    return 1;
}

gmexport const char* buffer_read_hex(double id, double len) {
    ///buffer_read_hex(id,len)
    //id: buffer index
    //len: length in bytes
    //returns: string
    //Reads an amount of expanded hex-codes from the buffer as a string.
    //This will deconvert the binary data to readable hex codes. For example, "cat" in the buffer becomes "636174" when read.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return "";
    unsigned int l = gm_cast<unsigned int>(len);
    gmreturnstring = b->ReadHex(l);
    return gmreturnstring.c_str();
}

gmexport double buffer_write_hex(double id, const char* string) {
    ///buffer_write_hex(id,string)
    //id: buffer index
    //string: string to write
    //Writes a string of expanded hex-codes to the buffer as data.
    //This will convert the hex codes in the string into binary data. For example, "636174" becomes "cat" in the buffer.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->WriteHex(string, strlen(string));
    return 1;
}

gmexport const char* buffer_encode_base64(double id, double len) {
    ///buffer_encode_base64(id,len)
    //id: buffer index
    //len: length in bytes to encode
    //returns: string
    //This will encode the buffer into its base64 representation. For example, "cat" becomes "Y2F0".
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return "";
    unsigned int l = gm_cast<unsigned int>(len);
    gmreturnstring = b->ReadBase64(l);
    return gmreturnstring.c_str();
}

gmexport double buffer_decode_base64(double id, const char* string) {
    ///buffer_decode_base64(id,string)
    //id: buffer index
    //string: base64 string to decode
    //This will decode the base64 data into the buffer. For example, "Y2F0" becomes "cat".
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    b->WriteBase64(string, strlen(string));
    return 1;
}

gmexport double buffer_write_buffer(double id, double id2) {
    ///buffer_copy(to,from)
    //to: destination buffer id
    //from: source buffer id
    //Copies the data in the source buffer to the end of the destination buffer.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    Buffer *b2 = gmdata.FindBuffer(gm_cast<unsigned int>(id2));
    if(b2 == NULL) return 0;
    b->WriteBuffer(b2);
    b->SetPos(b->GetLength() + b2->GetLength());
    return 1;
}

gmexport double buffer_write_buffer_part(double id, double id2, double pos, double len) {
    ///buffer_copy_part(to,from,pos,len)
    //to: destination buffer id
    //from: source buffer id
    //pos/len: part of the source buffer to copy
    //Copies the part of the data in the source buffer to the end of the destination buffer.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    Buffer *b2 = gmdata.FindBuffer(gm_cast<unsigned int>(id2));
    if(b2 == NULL) return 0;
    b->WriteBufferPart(b2, gm_cast<unsigned int>(pos), gm_cast<unsigned int>(len));
    b->SetPos(b->GetLength() + gm_cast<unsigned int>(len));
    return 1;
}

gmexport double buffer_get_address(double id/*, double asrealpointer*/) {
    ///buffer_get_address(id)
    //id: buffer index
    //returns: address of the buffer for use with dlls
    //This function obtains the memory address of a buffer so that other dll extensions may write to or read from it.
    //Note that you should always preallocate the buffer appropriately using buffer_set_size before passing it on to a dll for writing.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if (b == NULL) return 0;

    /*if (gm_cast<bool>(asrealpointer)) {
        // realpointer aka packed pointer (safe)
        static_assert((sizeof(double) >= sizeof(char*)), "realpointer size check fail.");
        double vv = 0.0;
        *reinterpret_cast<char**>(&vv) = b->GetData();
        return vv;
    }
    else {*/
        // cast pointer to double (UNSAFE!)
        // this is what window_handle() and get_function_address() in native GM do.
        return (double)((uintptr_t)b->GetData());
    //}
}

/*
static char ptrstringbuf[32];

gmexport const char* buffer_get_address_string(double id, double ashexstring) {
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if (b == NULL) return 0;

    // clear the buffer
    memset(&ptrstringbuf, 0, sizeof(ptrstringbuf));

    // get pointer as an unsigned pointer int.
    uintptr_t val = (uintptr_t)b->GetData();

    if (gm_cast<bool>(ashexstring)) {
        // as a hex string
        snprintf(ptrstringbuf, sizeof(ptrstringbuf) - 1, "%" PRIxPTR, val);
    }
    else {
        // uintptr_t to string
        snprintf(ptrstringbuf, sizeof(ptrstringbuf) - 1, "%" PRIuPTR, val);
    }

    return ptrstringbuf;
}
*/

gmexport double buffer_peek(double id,double pos) {
    ///buffer_peek(id,pos)
    //id: buffer index
    //pos: position to read
    //returns: byte at position in the buffer
    //Reads a single byte from the buffer without moving the caret.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    unsigned int oldpos = b->GetPos();
    b->SetPos(pos);
    double ret = b->ReadType<uint8_t>();
    b->SetPos(oldpos);
    return ret;
}

gmexport double buffer_poke(double id,double pos,double byte) {
    ///buffer_poke(id,pos,value)
    //id: buffer index
    //pos: position to read
    //value: value to write
    //Writes a single byte to a location in the buffer without moving the caret.
    
    Buffer *b = gmdata.FindBuffer(gm_cast<unsigned int>(id));
    if(b == NULL) return 0;
    unsigned int oldpos = b->GetPos();
    b->SetPos(pos);
    b->WriteType<uint8_t>(gm_cast<uint8_t>(byte));
    b->SetPos(oldpos);
    return 1;
}
