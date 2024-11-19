#pragma once
#ifndef ENCDEC_ALGO_INCLUDED
#define ENCDEC_ALGO_INCLUDED

#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include "data.hpp"


namespace NETW_MSG
{
	bool encode_idea(cryptoAL::cryptodata& data_temp, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_temp_next);
	bool decode_idea(cryptoAL::cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_decrypted);
}

#endif
