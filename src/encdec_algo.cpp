#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <ctype.h>

#include "../include/encdec_algo.hpp"
#include "../include/main_global.hpp"

namespace NETW_MSG
{
    bool encode_idea(cryptoAL::cryptodata& data_temp, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_temp_next)
    {
        bool r = true;
        char c;

        if (data_temp.buffer.size() % 8 != 0)
        {
            r = false;
            std::stringstream ss;
            ss << "ERROR " << "encode_idea data file must be multiple of 8 bytes idea: " << data_temp.buffer.size() << std::endl;
            main_global::log(ss.str());
            return r;
        }
        if (data_temp.buffer.size() == 0)
        {
            r = false;
            std::stringstream ss;
            ss << "ERROR " << "encode_idea data file is empty " << std::endl;
            main_global::log(ss.str());
            return r;
        }

        if (key_size % 16 != 0)
        {
            r = false;
            std::stringstream ss;
            ss << "ERROR " << "encode_idea key must be multiple of 16 bytes: " << key_size << std::endl;
            main_global::log(ss.str());
            return r;
        }
        if (key_size == 0)
        {
            std::stringstream ss;
            ss << "ERROR encode_idea - key_size = 0 " << std::endl;
            main_global::log(ss.str());
            return false;
        }

        uint32_t nround = 1;
        uint32_t nblock = data_temp.buffer.size() / 8;
        uint32_t nkeys = key_size / 16;

        if (data_temp.buffer.size() > 0)
        {
            if (key_size > data_temp.buffer.size())
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
        }

        //if (verbose)
        //{
        //	std::cout.flush();
        //	std::string message = "Encoding idea";
        //	size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
        //	std::string message_space(sz, ' ');
        //	std::cout << message << message_space <<
        //		", number of rounds : " << nround <<
        //		", number of blocks (8 bytes): " << nblock <<
        //		", number of keys (16 bytes): " << nkeys << ", shuffling: " << shufflePerc << "%" << std::endl;
        //}

        uint8_t KEY[16 + 1];
        uint8_t DATA[8 + 1];
        uint32_t key_idx = 0;

        for (size_t roundi = 0; roundi < nround; roundi++)
        {
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            for (size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for (size_t j = 0; j < 8; j++)
                    {
                        c = data_temp.buffer.getdata()[8 * blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0; // Data must be 128 bits long
                }
                else
                {
                    for (size_t j = 0; j < 8; j++)
                    {
                        c = data_temp_next.buffer.getdata()[8 * blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0; // Data must be 128 bits long
                }

                for (size_t j = 0; j < 16; j++)
                {
                    c = key[16 * key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx = 0;

                idea algo;
                algo.IDEA(DATA, KEY, true);

                data_temp_next.buffer.write((char*)&DATA[0], (uint32_t)8, -1);
            }
        }

        return r;
    }

    bool decode_idea(cryptoAL::cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_decrypted)
    {
        bool r = true;
        char c;

        if (key_size % 16 != 0)
        {
            r = false;
            std::stringstream ss;
            ss << "ERROR " << "decode_idea key must be multiple of 16 bytes " << key_size << std::endl;
            main_global::log(ss.str());
            return r;
        }
        if (data_encrypted.buffer.size() % 8 != 0)
        {
            r = false;
            std::stringstream ss;
            ss << "ERROR " << "decode_idea data must be multiple of 8 bytes " << data_encrypted.buffer.size() << std::endl;
            main_global::log(ss.str());
            return r;
        }
        if (key_size == 0)
        {
            std::stringstream ss;
            ss << "ERROR decode_sidea - key_size = 0 " << "" << std::endl;
            main_global::log(ss.str());
            return false;
        }
        if (data_encrypted.buffer.size() == 0)
        {
            std::stringstream ss;
            ss << "ERROR decode_sidea - data file is empty " << std::endl;
            main_global::log(ss.str());
            return false;
        }

        uint32_t nround = 1;
        uint32_t nblock = data_encrypted.buffer.size() / 8;
        uint32_t nkeys = key_size / 16;


        if (data_encrypted.buffer.size() > 0)
        {
            if (key_size > data_encrypted.buffer.size())
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
        }

        //if (verbose)
        //{
        //	std::string message = "Decoding idea";
        //	size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
        //	std::string message_space(sz, ' ');
        //	std::cout << message << message_space <<
        //		", number of rounds : " << nround <<
        //		", number of blocks (8 bytes): " << nblock <<
        //		", number of keys (16 bytes): " << nkeys << std::endl;
        //}

        uint8_t KEY[16 + 1];
        uint8_t DATA[8 + 1];
        uint32_t key_idx = 0;

        for (size_t roundi = 0; roundi < nround; roundi++)
        {
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) * nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for (size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for (size_t j = 0; j < 8; j++)
                    {
                        c = data_encrypted.buffer.getdata()[8 * blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0;
                }
                else
                {
                    for (size_t j = 0; j < 8; j++)
                    {
                        c = data_decrypted.buffer.getdata()[8 * blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0;
                }

                for (size_t j = 0; j < 16; j++)
                {
                    c = key[16 * key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx = 0;

                idea algo;
                algo.IDEA(DATA, KEY, false);

                data_decrypted.buffer.write((char*)&DATA[0], 8, -1);
            }
        }

        return r;
    }
}
