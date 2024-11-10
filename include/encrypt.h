#ifndef _INCLUDES_encrypt_H
#define _INCLUDES_encrypt_H

#include "Base64.h"
#include "vigenere.hpp"
#include <iostream>
#include <string>


std::string encrypt_simple_string(std::string& msg, std::string& key);

// https://stackoverflow.com/questions/17316506/strip-invalid-utf8-from-string-in-c-c
std::string sanitize_utf8(std::string& str);

std::string decrypt_simple_string(std::string& encrypted_msg, std::string& key);

/*[[maybe_unused]] */ /*static */std::string get_summary_hex(const char* buffer, uint32_t buf_len);

#endif // _INCLUDES_encrypt_H
