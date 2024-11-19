#ifndef _INCLUDES_encrypt_H
#define _INCLUDES_encrypt_H

#ifdef _WIN32
//
#else
#include <cstdint>
#endif

#include <iostream>
#include <string>
#include "Base64.h"
#include "vigenere.hpp"


std::string encrypt_simple_string(const std::string& msg, const std::string& key);
std::string decrypt_simple_string(const std::string& encrypted_msg, const std::string& key);

// https://stackoverflow.com/questions/17316506/strip-invalid-utf8-from-string-in-c-c
std::string sanitize_utf8(const std::string& str);

#endif // _INCLUDES_encrypt_H
