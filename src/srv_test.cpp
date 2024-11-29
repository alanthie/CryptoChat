#include <iostream>
#include <limits>
#include <csignal>
#include <chrono>
#include "../include/crypto_server.hpp"
#include "../include/chat_srv.hpp"
#include "../include/cfg_srv.hpp"
#include "../include/string_util.hpp"
#include "../include/encdec_algo.hpp"


namespace crypto_socket
{

void crypto_server::server_test()
{
    // TEST
    //{
    //	std::map<std::string, std::string> map_out;
    //	std::string out_error;
    //	bool r = NETW_MSG::challenge_read_from_file("C:\\cpp\\CryptoChat\\challenge.txt", map_out, out_error);
    //}

    //
    // TEST MSG_FILE_FRAGMENT_HEADER
    //{
    //	NETW_MSG::MSG_FILE_FRAGMENT_HEADER h;
    //	h.filename = "C:\\tmp\\f.txt";
    //	h.total_size = std::to_string(52);
    //	h.from = std::to_string(0);
    //	h.to = std::to_string(52-1);

    //	NETW_MSG::MSG_FILE_FRAGMENT_HEADER hh;
    //	bool r = hh.parse_header(h.make_header());

    //	std::vector<NETW_MSG::MSG_FILE_FRAGMENT_HEADER> vout;
    //	r = NETW_MSG::MSG_FILE_FRAGMENT_HEADER::make_fragments("C:\\tmp\\smartgit-win-24_1_0.zip", vout);
    //}

    // TEST ENCRYPTION
    char buff[4];
    NETW_MSG::MSG::uint4ToByte(3453, buff);
    {
        uint32_t i = NETW_MSG::MSG::byteToUInt4(buff);
        if (i != 3453)
            throw std::runtime_error("Default key encryption not working");
    }

    const int N_SIZE_TEST = 10;
    {
        std::string key("12345678901234561234567890123456");
        if (this->check_default_encrypt(key) == false)
        {
            throw std::runtime_error("Default encryption not working");
        }

        key = "1234567890123456";
        if (this->check_idea_encrypt(key) == false)
        {
            throw std::runtime_error("IDEA encryption not working");
        }

        key = "1234567890123456123456789012345612345678901234561234567890123456";
        if (this->check_salsa_encrypt(key) == false)
        {
            throw std::runtime_error("Salsa20 encryption not working");
        }

        key = getDEFAULT_KEY();
        if (this->check_default_encrypt(key) == false)
        {
            throw std::runtime_error("Default key encryption not working");
        }

        // TEST cryptoAL_vigenere
        for(int i=0;i<N_SIZE_TEST;i++)
        {
            std::string bkey = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

            std::string bdat = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE / 2);
            std::string benc = cryptoAL_vigenere::encrypt_vigenere(bdat, bkey);
            std::string bdec = cryptoAL_vigenere::decrypt_vigenere(benc, bkey);
            if (bdat != bdec)
            {
                throw std::runtime_error("Vigenere key encryption not working on Base64");
            }
        }

        // TEST IDEA
        //			{
        //				idea id;
        //
        //				uint16_t data[4] = { 54,36,454,345 };
        //				uint16_t key[8] = { 345,3453,5,3453,5,3556,46,4567 };
        //				id.IDEA(data, key, true);
        //				id.IDEA(data, key, false);
        //			}
        for(int i=0;i<N_SIZE_TEST;i++)
        {
            std::string bkey = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE/8);
            std::string bdat = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE / 2);
            cryptoAL::cryptodata datain;
            cryptoAL::cryptodata dataenc;
            cryptoAL::cryptodata dataout;
            datain.buffer.write(bdat.data(), bdat.size());

            // "encode_idea data file must be multiple of 8 bytes idea: "
            // "encode_idea key must be multiple of 16 bytes: "

            bool r = NETW_MSG::encode_idea(datain, bkey.data(), bkey.size(), dataenc);
            if (r) r = NETW_MSG::decode_idea(dataenc, bkey.data(), bkey.size(), dataout);
            if (r) if (dataout.buffer.size() != bdat.size()) r = false;
            if (r) if (memcmp(dataout.buffer.getdata(),bdat.data(), bdat.size())!=0) r = false;
            if (!r)
            {
                throw std::runtime_error("IDEA key encryption not working on Base64");
            }
        }
    }
}

bool crypto_server::check_default_encrypt(std::string& key)
{
    std::stringstream serr;
    NETW_MSG::MSG m, m2, m3;
    m.make_msg(NETW_MSG::MSG_TEXT, "Hello Test", key);
    std::string sm = m.get_data_as_string();

    uint32_t crc1 = NETW_MSG::MSG::byteToUInt4((char*)m.buffer+NETW_MSG::MESSAGE_CRC_START);

    uint32_t crc;
    m2.make_encrypt_msg(m, key, 0, 0, 0, serr);
    std::string sm2 = m2.get_data_as_string();
    uint32_t crc2 = NETW_MSG::MSG::byteToUInt4((char*)m2.buffer+NETW_MSG::MESSAGE_CRC_START);

    m3.make_decrypt_msg(m2, key, crc, serr);
    std::string sm3 = m3.get_data_as_string();
    uint32_t crc3 = NETW_MSG::MSG::byteToUInt4((char*)m3.buffer+NETW_MSG::MESSAGE_CRC_START);

    return m.is_same(m3);
}

bool crypto_server::check_idea_encrypt(std::string& key)
{
    NETW_MSG::MSG m, m2, m3;

    std::string s0 = "Hello Test Hello Test jjjjjjjjjjj";
    m.make_msg(NETW_MSG::MSG_TEXT, s0, key);

    m2.make_with_padding(m);
    m3.make_removing_padding(m2);
    if (!m.is_same(m3))
    {
        return false;
    }

    std::string ss0 = "DSAFDF FS Df";
    std::string ss1 = NETW_MSG::MSG::add_padding(ss0);
    std::string ss2 = NETW_MSG::MSG::remove_padding(ss1);
    if (ss0 != ss2)
    {
        return false;
    }

    std::string s2 = m2.get_data_as_string();
    cryptoAL::cryptodata data_temp;
    data_temp.buffer.write((char*)s2.data(), s2.size());

    cryptoAL::cryptodata data_temp_out;
    bool r = NETW_MSG::encode_idea(data_temp, key.data(), key.size(), data_temp_out);
    if (r)
    {
        std::string s3 = std::string(data_temp_out.buffer.getdata(), data_temp_out.buffer.size());

        cryptoAL::cryptodata data_temp_out2;
        r = NETW_MSG::decode_idea(data_temp_out, key.data(), key.size(), data_temp_out2);
        if (!r)
        {
            return false;
        }
        else
        {
            std::string s4 = std::string(data_temp_out2.buffer.getdata(), data_temp_out2.buffer.size());
            if (s4 == s2) return true;
            return false;
        }
    }
    else
    {
        return false;
    }
    return r;
}

bool crypto_server::check_salsa_encrypt(std::string& key)
{
    NETW_MSG::MSG m, m2, m3;

    std::string s0 = "Hello Test Hello Test jjjjjjjjjjj";
    m.make_msg(NETW_MSG::MSG_TEXT, s0, key);

    m2.make_with_padding(m);
    m3.make_removing_padding(m2);
    if (!m.is_same(m3))
    {
        return false;
    }

    std::string ss0 = "DSAFDF FS Df";
    std::string ss1 = NETW_MSG::MSG::add_padding(ss0);
    std::string ss2 = NETW_MSG::MSG::remove_padding(ss1);
    if (ss0 != ss2)
    {
        return false;
    }

    std::string s2 = m2.get_data_as_string();
    cryptoAL::cryptodata data_temp;
    data_temp.buffer.write((char*)s2.data(), s2.size());

    cryptoAL::cryptodata data_temp_out;
    bool r = NETW_MSG::encode_salsa20(data_temp, key.data(), key.size(), data_temp_out);
    if (r)
    {
        std::string s3 = std::string(data_temp_out.buffer.getdata(), data_temp_out.buffer.size());

        cryptoAL::cryptodata data_temp_out2;
        r = NETW_MSG::decode_salsa20(data_temp_out, key.data(), key.size(), data_temp_out2);
        if (!r)
        {
            return false;
        }
        else
        {
            std::string s4 = std::string(data_temp_out2.buffer.getdata(), data_temp_out2.buffer.size());
            if (s4 == s2) return true;
            return false;
        }
    }
    else
    {
        return false;
    }
    return r;
}
}
