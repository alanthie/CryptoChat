#pragma once
#ifndef ENCDEC_ALGO_INCLUDED
#define ENCDEC_ALGO_INCLUDED

#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include "crypto_const.hpp"
#include "data.hpp"


namespace NETW_MSG
{
	bool encode_idea(cryptoAL::cryptodata& data_temp, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_temp_next, bool test = false);
	bool decode_idea(cryptoAL::cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_decrypted);

	bool encode_string_idea(const std::string& sin, const std::string& key, std::string& sout);
	bool decode_string_idea(const std::string& sin, const std::string& key, std::string& sout);


	bool encode_salsa20(cryptoAL::cryptodata& data_temp, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_temp_next);
	bool decode_salsa20(cryptoAL::cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_decrypted);

	bool encode_string_salsa20(const std::string& sin, const std::string& key, std::string& sout);
	bool decode_string_salsa20(const std::string& sin, const std::string& key, std::string& sout);
}

#endif
