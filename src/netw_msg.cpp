#include "../include/crypto_const.hpp"
#include "../include/netw_msg.hpp"
#include "../include/main_global.hpp"
#include "../include/crc32a.hpp"
#include "../include/encdec_algo.hpp"

namespace NETW_MSG
{
    size_t MSG::size() { return buffer_len; };

    uint8_t* MSG::get_buffer()
    {
        return buffer;
    }

    std::string MSG::get_data_as_string()
    {
        if (buffer_len > MESSAGE_HEADER)
        {
            return std::string((char*)buffer + MESSAGE_HEADER, buffer_len - MESSAGE_HEADER);
        }
        return std::string{};
    }

    bool MSG::is_same(MSG& msgin)
    {
        if (this->type_msg != msgin.type_msg) return false;
        if (this->buffer_len != msgin.buffer_len) return false;
        if (memcmp(this->buffer, msgin.buffer, buffer_len) != 0) return false;
        return true;
    }

    std::string MSG::make_key_64(const std::string& keyin, const std::string& extend)
    {
        std::string sout = keyin;
        uint32_t len_data = keyin.size();

        uint32_t padding = MESSAGE_FACTOR - (len_data % MESSAGE_FACTOR); // 0-63
        for (int i = 0; i < padding; i++)
        {
            sout.push_back(extend[i % extend.size()]);
        }
        return sout;
    }

    std::string MSG::add_padding(const std::string& sin)
    {
        std::string sout = sin;

        // MSG = MESSAGE_HEADER + data + [____pad_end_number(1-64)]
        uint32_t len_data = sin.size();

        uint32_t padding = MESSAGE_FACTOR - (len_data % MESSAGE_FACTOR); // 0-63
        if (padding == 0) padding = 64;
        char cpadding = (char)(uint8_t)padding;

        char space[1]{ ' ' };
        for (int i = 0; i < padding; i++) sout.append(" ");
        sout[sout.size() - 1] = (char)cpadding;

        return sout;
    }

    std::string MSG::remove_padding(const std::string& sin)
    {
        uint8_t padding = (uint8_t)sin[sin.size() - 1];
        std::string sout = sin.substr(0, sin.size() - padding);
        return sout;
    }

    void MSG::make_with_padding(MSG& m)
    {
        // MSG = MESSAGE_HEADER + data + [____pad_end_number(1-64)]
        uint32_t len_data = m.buffer_len - MESSAGE_HEADER;

        uint32_t padding = MESSAGE_FACTOR - ((len_data + MESSAGE_HEADER) % MESSAGE_FACTOR); // 0-63
        if (padding == 0) padding = 64;
        char cpadding = (char)(uint8_t)padding;

        buffer_len = len_data + MESSAGE_HEADER + padding;
        buffer = new uint8_t[buffer_len]{ 0 };
        type_msg = m.buffer[0];
        memcpy(buffer, m.buffer, m.buffer_len);

        char space[1]{ ' ' };
        for (int i = 0; i < padding; i++) memcpy(buffer + buffer_len - 1 - i, space, 1);
        memcpy(buffer + buffer_len - 1, &cpadding, 1);
    }

    void MSG::make_removing_padding(MSG& m)
    {
        // MSG = MESSAGE_HEADER + data + [____pad_end_number(1-64)]
        uint32_t padding = m.buffer[m.buffer_len - 1];

        buffer_len = m.buffer_len - padding;
        buffer = new uint8_t[buffer_len]{ 0 };
        type_msg = m.buffer[0];
        memcpy(buffer, m.buffer, m.buffer_len - padding);
    }

    bool MSG::make_encrypt_msg(MSG& msgin, const std::string& key, uint8_t crypto_flag, uint8_t from_user, uint8_t to_user)
    {
        std::vector<char> vmsgin(msgin.buffer_len - MESSAGE_HEADER);
        for (size_t i = MESSAGE_HEADER; i < msgin.buffer_len; i++) vmsgin[i - MESSAGE_HEADER] = msgin.buffer[i];

        // ENCRYPTION
        std::string b64_str = Base64::encode(vmsgin);
        std::string s_encrypted = encrypt_simple_string(b64_str, key);

        // ENCRYPTION
        std::string s_encrypted_with_pad = NETW_MSG::MSG::add_padding(s_encrypted);
        std::string s_encrypted2;
        bool r = NETW_MSG::encode_string_idea(s_encrypted_with_pad, key, s_encrypted2);
        if (!r)
        {
            std::cerr << "encode_string_idea FAILED" << std::endl;
            return false;
        }

        // ENCRYPTION
        s_encrypted_with_pad = NETW_MSG::MSG::add_padding(s_encrypted2);
        std::string s_encrypted3;
        r = NETW_MSG::encode_string_salsa20(s_encrypted_with_pad, key, s_encrypted3);
        if (!r)
        {
            std::cerr << "encode_string_salsa20 FAILED" << std::endl;
            return false;
        }

        SHA256 sha;
        sha.update((uint8_t*)key.data(), key.size());
        uint8_t* digestkey = sha.digest();

        CRC32 chk;
        chk.update((char*)msgin.buffer + MESSAGE_HEADER, msgin.buffer_len - MESSAGE_HEADER);
		uint32_t crc = chk.get_hash();

        //uint8_t original_flag = msgin.buffer[MESSAGE_FLAG_START];

        make_msg_with_crc_and_flag(msgin.type_msg, s_encrypted3, digestkey, crc, crypto_flag, from_user, to_user);

        //std::cout << "make_encrypt_msg - exit - this->buffer_len - MESSAGE_HEADER " << this->buffer_len - MESSAGE_HEADER << "\n";

        delete[] digestkey;

        if (DEBUG_INFO)
        {
            std::stringstream ss;
            ss << "make_encrypt_msg ["
                + file_util::get_summary_hex((char*)msgin.buffer + MESSAGE_HEADER, msgin.buffer_len - MESSAGE_HEADER) + "]=>["
                + file_util::get_summary_hex((char*)this->buffer + MESSAGE_HEADER, this->buffer_len - MESSAGE_HEADER)
                + "]" << std::endl;
            main_global::log(ss.str());
        }

        return true;
    }

    bool MSG::make_decrypt_msg(MSG& msgin, const std::string& key, uint32_t& crc)
    {
        //std::cout << "make_decrypt_msg - entry - msgin.buffer_len - MESSAGE_HEADER " << msgin.buffer_len - MESSAGE_HEADER << "\n";

        std::string s = msgin.get_data_as_string(); // including padding space
        if ((s.size() % MESSAGE_FACTOR) != 0)
        {
            std::cout << "data is not 64x" << std::endl;
        }

        // DECRYPTION
        std::string s_decrypted1;
        bool r = NETW_MSG::decode_string_salsa20(s, key, s_decrypted1);
        if (!r)
        {
            std::cout << "decode_string_salsa20 FAILED" << std::endl;
            return false;
        }
        std::string s_derypted_without_pad = NETW_MSG::MSG::remove_padding(s_decrypted1);

        // DECRYPTION
        std::string s_decrypted2;
        r = NETW_MSG::decode_string_idea(s_derypted_without_pad, key, s_decrypted2);
        if (!r)
        {
            std::cout << "decode_string_idea FAILED" << std::endl;
            return false;
        }
        s_derypted_without_pad = NETW_MSG::MSG::remove_padding(s_decrypted2);

        // DECRYPTION
        std::string b64_encoded_str = decrypt_simple_string(s_derypted_without_pad, key);
        std::vector<char> b64_decode_vec = Base64::decode(b64_encoded_str);

        uint32_t len = MESSAGE_HEADER + b64_decode_vec.size();

        if (buffer != nullptr) delete buffer;
        buffer = new uint8_t[len]{ 0 };
        buffer_len = len;

        type_msg = msgin.type_msg;
        buffer[0] = msgin.type_msg;
        MSG::uint4ToByte(buffer_len, (char*)buffer + 1);
        memcpy(buffer + MESSAGE_KEYDIGEST_START, 	msgin.buffer + MESSAGE_KEYDIGEST_START, 32);
		memcpy(buffer + MESSAGE_SIGNATURE_START, 	msgin.buffer + MESSAGE_SIGNATURE_START, 20);
		memcpy(buffer + MESSAGE_FLAG_START,	        msgin.buffer + MESSAGE_FLAG_START, 1);
		memcpy(buffer + MESSAGE_CRC_START, 			msgin.buffer + MESSAGE_CRC_START, 4);
		memcpy(buffer + MESSAGE_MISC_START, 		msgin.buffer + MESSAGE_MISC_START, 2);
        memcpy(buffer + MESSAGE_MISC_END,           msgin.buffer + MESSAGE_MISC_END, 64);
        for (size_t i = 0; i < b64_decode_vec.size(); i++) buffer[i + MESSAGE_HEADER] = b64_decode_vec[i];

        crc = MSG::byteToUInt4((char*)buffer + MESSAGE_CRC_START);

        //std::cout << "make_decrypt_msg - exit - this->buffer_len - MESSAGE_HEADER " << this->buffer_len - MESSAGE_HEADER << "\n";

        if (DEBUG_INFO)
        {
            std::stringstream ss;
            ss << "make_decrypt_msg ["
                + file_util::get_summary_hex((char*)msgin.buffer + MESSAGE_HEADER, msgin.buffer_len - MESSAGE_HEADER) + "]=>["
                + file_util::get_summary_hex((char*)this->buffer + MESSAGE_HEADER, this->buffer_len - MESSAGE_HEADER)
                << std::endl;
            main_global::log(ss.str());
        }

        return true;
    }

    void MSG::make_msg(uint8_t t, const std::string& s, const std::string& key)
    {
        SHA256 sha;
        sha.update((uint8_t*)key.data(), key.size());
        uint8_t* digestkey = sha.digest();

        if (s.size() >= NETW_MSG::MESSAGE_SIZE - MESSAGE_HEADER)
        {
            std::string smsg = s.substr(0, NETW_MSG::MESSAGE_SIZE - MESSAGE_HEADER);
            make_msg(t, smsg.size(), (uint8_t*)smsg.data(), digestkey);

            std::stringstream ss;
            ss << "WARNING message truncated" << std::endl;
            main_global::log(ss.str());
        }
        else
        {
            make_msg(t, s.size(), (uint8_t*)s.data(), digestkey);
        }
        delete[]digestkey;
    }

    void MSG::make_msg_with_crc_and_flag_buffer( uint8_t t,
                        uint32_t len_data, uint8_t* data,
                        uint8_t* digestkey, uint32_t crc, uint8_t flag_original, uint32_t from_user, uint32_t to_user)
    {
        if (data == nullptr) return;

        type_msg = t;

        buffer_len = len_data + MESSAGE_HEADER;// +padding;
        if (buffer != nullptr) delete buffer;
        buffer = new uint8_t[buffer_len]{ 0 };

        buffer[0] = t;
        MSG::uint4ToByte(buffer_len, (char*)buffer + 1);
        memcpy(buffer + MESSAGE_KEYDIGEST_START, digestkey, 32);
		memcpy(buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20);
		memcpy(buffer + MESSAGE_FLAG_START, MESSAGE_LAST, 1+4+2);
        buffer[MESSAGE_FLAG_START] = flag_original;
        MSG::uint4ToByte(crc, (char*)buffer + MESSAGE_CRC_START);
        NETW_MSG::MSG::uint4ToByte(from_user, (char*)buffer + NETW_MSG::MESSAGE_FROM_START);
        NETW_MSG::MSG::uint4ToByte(to_user, (char*)buffer + NETW_MSG::MESSAGE_TO_START);

        memcpy(buffer + MESSAGE_HEADER, data, len_data);
    }

    void MSG::make_msg( uint8_t t,
                        uint32_t len_data, uint8_t* data,
                        uint8_t* digestkey)
    {
        if (data == nullptr) return;

        type_msg = t;

        buffer_len = len_data + MESSAGE_HEADER;// +padding;
        buffer = new uint8_t[buffer_len]{ 0 };

        buffer[0] = t;
        MSG::uint4ToByte(buffer_len, (char*)buffer + 1);
        memcpy(buffer + MESSAGE_KEYDIGEST_START, digestkey, 32);
		memcpy(buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20);
		memcpy(buffer + MESSAGE_FLAG_START, MESSAGE_LAST, 1+4+2);
        //har buff[64] = { 0 };
        //memcpy(buffer + MESSAGE_MISC_END, buff, 64);
        memcpy(buffer + MESSAGE_HEADER, data, len_data);

        CRC32 chk;
        chk.update((char*)buffer + MESSAGE_HEADER, buffer_len - MESSAGE_HEADER);
		uint32_t crc = chk.get_hash();
		MSG::uint4ToByte(crc, (char*)buffer + MESSAGE_CRC_START);

		// flag????????
    }

    void MSG::make_msg(uint8_t* buffer_in, size_t len)
    {
        if (buffer_in == nullptr) return;
        if (len == 0) return;

        buffer = new uint8_t[len]{ 0 };
        type_msg = buffer_in[0];
        buffer_len = (uint32_t)len;
        memcpy(buffer, buffer_in, len);
    }

    void MSG::make_msg(uint8_t t, const std::string& s, uint8_t* digestkey)
    {
        make_msg(t, (uint32_t)s.size(), (uint8_t*)s.data(), digestkey);
    }
    void MSG::make_msg_with_crc_and_flag(uint8_t t, const std::string& s, uint8_t* digestkey, uint32_t crc, uint8_t flag, uint32_t from_user, uint32_t to_user)
    {
        make_msg_with_crc_and_flag_buffer(t, (uint32_t)s.size(), (uint8_t*)s.data(), digestkey, crc, flag, from_user, to_user);
    }

    bool MSG::parse(char* message_buffer, size_t len, std::string key, std::string previous_key, std::string pending_key)
    {
        std::stringstream ss;
        ss << "MSG::parse() size= " << len << std::endl;

        if (len < MESSAGE_HEADER)
        {
            type_msg = MSG_EMPTY;
            ss << "WARNING MSG_EMPTY msg_len = " << len << std::endl;
            main_global::log(ss.str());
            return false;
        }

        if (key.size() == 0)
        {
            ss << "WARNING KEY EMPTY " << std::endl;
            main_global::log(ss.str());
            return false;
        }

        uint32_t crc;
        uint32_t expected_len = MSG::byteToUInt4(message_buffer + 1);
        if (expected_len != len)
        {
            ss << "WARNING parsing - len msg is unexpected " << len << " vs " << expected_len << std::endl;
            main_global::log(ss.str());
            return false;
        }

        SHA256 sha;
        sha.update((uint8_t*)key.data(), key.size());
        uint8_t* digestkey = sha.digest();

        if (memcmp(message_buffer + MESSAGE_KEYDIGEST_START, digestkey, 32) != 0)
        {
            delete[]digestkey;
            ss << "WARNING INVALID key digest in MSG::parse() " << std::endl;

            if (!pending_key.empty())
            {
                SHA256 shapending;
                shapending.update((uint8_t*)pending_key.data(), pending_key.size());
                uint8_t* digestkeypending = shapending.digest();

                if (memcmp(message_buffer + MESSAGE_KEYDIGEST_START, digestkeypending, 32) != 0)
                {
                    ss << "WARNING pending key not working" << std::endl;
                    delete[]digestkeypending;
                }
                else
                {
                    delete[]digestkeypending;

					 if (memcmp(message_buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20) != 0)
					 {
                        ss << "WARNING invalid signature in pending key" << std::endl;
					 }
					 else
					 {
                        ss << "INFO using pending key" << std::endl;
                        main_global::log(ss.str());

                        MSG m;
                        m.make_msg((uint8_t*)message_buffer, len);
                        return this->make_decrypt_msg(m, pending_key, crc);
                    }
                }
            }
            else
            {
                ss << "WARNING no pending key" << std::endl;
            }

            if (!previous_key.empty())
            {
                SHA256 shaprevious;
                shaprevious.update((uint8_t*)previous_key.data(), previous_key.size());
                uint8_t* digestkeyprevious = shaprevious.digest();

                if (memcmp(message_buffer + MESSAGE_KEYDIGEST_START, digestkeyprevious, 32) != 0)
                {
                    ss << "WARNING previous key not working" << std::endl;
                    delete[]digestkeyprevious;
                }
                else
                {
                    if (memcmp(message_buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20) != 0)
                    {
                        ss << "WARNING invalid signature in previous key" << std::endl;
                    }
                    else
                    {
                        delete[]digestkeyprevious;
                        ss << "INFO using previous key" << std::endl;
                        main_global::log(ss.str());

                        MSG m;
                        m.make_msg((uint8_t*)message_buffer, len);
                        return this->make_decrypt_msg(m, previous_key, crc);
                    }
                }
            }
            else
            {
                ss << "WARNING no previous key" << std::endl;
            }

            main_global::log(ss.str());
            return false;
        }
        else
        {
            delete[]digestkey;

            MSG m;
            m.make_msg((uint8_t*)message_buffer, len);
            main_global::log(ss.str());

            return this->make_decrypt_msg(m, key, crc);
        }
    }

    MSG::~MSG()
    {
        delete buffer;
        buffer = nullptr;
    }

}
