#ifndef vigenere_HPP
#define vigenere_HPP

#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <ctype.h>

namespace cryptoAL_vigenere
{
    static std::string AVAILABLE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

    int index(char c);
    bool is_valid_string(const std::string s);
    std::string extend_key(const std::string& msg, const std::string& key);
    std::string encrypt_vigenere(const std::string& msg, const std::string& key);
    std::string decrypt_vigenere(const std::string& encryptedMsg, const std::string& newKey);

    bool is_string_ok(const std::string& s);
};
#endif // vigenere_HPP
