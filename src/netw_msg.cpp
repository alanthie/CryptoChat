#include "../include/netw_msg.hpp"
#include "../include/main_global.hpp"
#include "../include/crc32a.hpp"

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
            return std::string((char*)buffer + MESSAGE_HEADER, buffer_len - MESSAGE_HEADER);
        return std::string{};
    }

    bool MSG::is_same(MSG& msgin)
    {
        if (this->type_msg != msgin.type_msg) return false;
        if (this->buffer_len != msgin.buffer_len) return false;
        if (memcmp(this->buffer, msgin.buffer, buffer_len) != 0) return false;
        return true;
    }

    void MSG::make_encrypt_msg(MSG& msgin, const std::string& key)
    {
        std::vector<char> vmsgin(msgin.buffer_len - MESSAGE_HEADER);
        for (size_t i = MESSAGE_HEADER; i < msgin.buffer_len; i++) vmsgin[i - MESSAGE_HEADER] = msgin.buffer[i];
        std::string b64_str = Base64::encode(vmsgin);
        std::string s = encrypt_simple_string(b64_str, key);

        SHA256 sha;
        sha.update((uint8_t*)key.data(), key.size());
        uint8_t* digestkey = sha.digest();

        CRC32 chk;
        chk.update((char*)msgin.buffer + MESSAGE_HEADER, msgin.buffer_len - MESSAGE_HEADER);
		uint32_t crc = chk.get_hash();

		//make_msg(msgin.type_msg, s, digestkey);
        make_msg_with_crc(msgin.type_msg, s, digestkey, crc);

        delete[] digestkey;

        if (DEBUG_INFO)
        {
            std::stringstream ss;
            ss << "Encrypt ["
                + file_util::get_summary_hex((char*)msgin.buffer + MESSAGE_HEADER, msgin.buffer_len - MESSAGE_HEADER) + "]=>["
                + file_util::get_summary_hex((char*)this->buffer + MESSAGE_HEADER, this->buffer_len - MESSAGE_HEADER)
                + "]" << std::endl;
            main_global::log(ss.str());
        }
    }

    void MSG::make_decrypt_msg(MSG& msgin, const std::string& key, uint32_t& crc)
    {
        std::string s = msgin.get_data_as_string();
        std::string b64_encoded_str = decrypt_simple_string(s, key);
        std::vector<char> b64_decode_vec = Base64::decode(b64_encoded_str);

        buffer = new uint8_t[MESSAGE_HEADER + b64_decode_vec.size()]{ 0 };
        buffer_len = MESSAGE_HEADER + (uint32_t)b64_decode_vec.size();
        type_msg = msgin.type_msg;

        buffer[0] = msgin.type_msg;
        MSG::uint4ToByte(buffer_len, (char*)buffer + 1);
        memcpy(buffer + MESSAGE_KEYDIGEST_START, 	msgin.buffer + MESSAGE_KEYDIGEST_START, 32);
		memcpy(buffer + MESSAGE_SIGNATURE_START, 	msgin.buffer + MESSAGE_SIGNATURE_START, 20);
		memcpy(buffer + MESSAGE_PADDING_START, 		msgin.buffer + MESSAGE_PADDING_START, 1);
		memcpy(buffer + MESSAGE_CRC_START, 			msgin.buffer + MESSAGE_CRC_START, 4);
		memcpy(buffer + MESSAGE_MISC_START, 		msgin.buffer + MESSAGE_MISC_START, 2);
        for (size_t i = 0; i < b64_decode_vec.size(); i++) buffer[i + MESSAGE_HEADER] = b64_decode_vec[i];

        crc = MSG::byteToUInt4((char*)buffer + MESSAGE_CRC_START);

        if (DEBUG_INFO)
        {
            std::stringstream ss;
            ss << "Decrypt ["
                + file_util::get_summary_hex((char*)msgin.buffer + MESSAGE_HEADER, msgin.buffer_len - MESSAGE_HEADER) + "]=>["
                + file_util::get_summary_hex((char*)this->buffer + MESSAGE_HEADER, this->buffer_len - MESSAGE_HEADER)
                << std::endl;
            main_global::log(ss.str());
        }
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

    void MSG::make_msg_with_crc_buffer( uint8_t t,
                        uint32_t len_data, uint8_t* data,
                        uint8_t* digestkey, uint32_t crc)
    {
        if (data == nullptr) return;

        type_msg = t;
        buffer_len = len_data + MESSAGE_HEADER;
        buffer = new uint8_t[buffer_len]{ 0 };

        buffer[0] = t;
        MSG::uint4ToByte(buffer_len, (char*)buffer + 1);
        memcpy(buffer + MESSAGE_KEYDIGEST_START, digestkey, 32);
		memcpy(buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20);
		memcpy(buffer + MESSAGE_PADDING_START, MESSAGE_LAST, 1+4+2);

		MSG::uint4ToByte(crc, (char*)buffer + MESSAGE_CRC_START);

        memcpy(buffer + MESSAGE_HEADER, data, len_data);
    }

    void MSG::make_msg( uint8_t t,
                        uint32_t len_data, uint8_t* data,
                        uint8_t* digestkey)
    {
        if (data == nullptr) return;
 
        type_msg = t;
        buffer_len = len_data + MESSAGE_HEADER;
        buffer = new uint8_t[buffer_len]{ 0 };

        buffer[0] = t;
        MSG::uint4ToByte(buffer_len, (char*)buffer + 1);
        memcpy(buffer + MESSAGE_KEYDIGEST_START, digestkey, 32);
		memcpy(buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20);
		memcpy(buffer + MESSAGE_PADDING_START, MESSAGE_LAST, 1+4+2);
        memcpy(buffer + MESSAGE_HEADER, data, len_data);

        CRC32 chk;
        chk.update((char*)buffer + MESSAGE_HEADER, buffer_len - MESSAGE_HEADER);
		uint32_t crc = chk.get_hash();
		MSG::uint4ToByte(crc, (char*)buffer + MESSAGE_CRC_START);
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
    void MSG::make_msg_with_crc(uint8_t t, const std::string& s, uint8_t* digestkey, uint32_t crc)
    {
        make_msg_with_crc_buffer(t, (uint32_t)s.size(), (uint8_t*)s.data(), digestkey, crc);
    }


    bool MSG::parse(char* message_buffer, size_t len, std::string key, std::string previous_key, std::string pending_key)
    {
        if (len < MESSAGE_HEADER)
        {
            type_msg = MSG_EMPTY;
            std::stringstream ss;
            ss << "WARNING MSG_EMPTY msg_len = " << len << std::endl;
            main_global::log(ss.str());
            return false;
        }

        if (key.size() == 0)
        {
            std::stringstream ss;
            ss << "WARNING KEY EMPTY " << std::endl;
            main_global::log(ss.str());
            return false;
        }

        if (len == MESSAGE_SIZE)
        {
            std::stringstream ss;
            ss  << "WARNING MSG(truncated), size = MESSAGE_SIZE" << std::endl;
            main_global::log(ss.str());
        }
        uint32_t crc;
        uint32_t expected_len = MSG::byteToUInt4(message_buffer + 1);
        if (expected_len != len)
        {
            std::stringstream ss;
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
            std::stringstream ss;
            ss << "WARNING INVALID key digest in MSG::parse() " << std::endl;
            main_global::log(ss.str());

            if (!pending_key.empty())
            {
                SHA256 shapending;
                shapending.update((uint8_t*)pending_key.data(), pending_key.size());
                uint8_t* digestkeypending = shapending.digest();

                if (memcmp(message_buffer + MESSAGE_KEYDIGEST_START, digestkeypending, 32) != 0)
                {
                    std::stringstream ss;
                    ss << "WARNING pending key not working" << std::endl;
                    main_global::log(ss.str());
                    delete[]digestkeypending;
                }
                else
                {
                    delete[]digestkeypending;

					 if (memcmp(message_buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20) != 0)
					 {
                        std::stringstream ss;
                        ss << "WARNING invalid signature in pending key" << std::endl;
                        main_global::log(ss.str());
					 }
					 else
					 {
                        std::stringstream ss;
                        ss << "INFO using pending key" << std::endl;
                        main_global::log(ss.str());

                        MSG m;
                        m.make_msg((uint8_t*)message_buffer, len);
                        this->make_decrypt_msg(m, pending_key, crc);
                        return true;
                    }
                }
            }
            else
            {
                std::stringstream ss;
                ss << "WARNING no pending key" << std::endl;
                main_global::log(ss.str());;
            }

            if (!previous_key.empty())
            {
                SHA256 shaprevious;
                shaprevious.update((uint8_t*)previous_key.data(), previous_key.size());
                uint8_t* digestkeyprevious = shaprevious.digest();

                if (memcmp(message_buffer + MESSAGE_KEYDIGEST_START, digestkeyprevious, 32) != 0)
                {
                    std::stringstream ss;
                    ss << "WARNING previous key not working" << std::endl;
                    main_global::log(ss.str());
                    delete[]digestkeyprevious;
                }
                else
                {
                    if (memcmp(message_buffer + MESSAGE_SIGNATURE_START, MESSAGE_SIGNATURE, 20) != 0)
                    {
                        std::stringstream ss;
                        ss << "WARNING invalid signature in previous key" << std::endl;
                        main_global::log(ss.str());
                    }
                    else
                    {
                        delete[]digestkeyprevious;
                        std::stringstream ss;
                        ss << "INFO using previous key" << std::endl;
                        main_global::log(ss.str());

                        MSG m;
                        m.make_msg((uint8_t*)message_buffer, len);
                        this->make_decrypt_msg(m, previous_key, crc);
                        return true;
                    }
                }
            }
            else
            {
                std::stringstream ss;
                ss << "WARNING no previous key" << std::endl;
                main_global::log(ss.str());
            }

            return false;
        }
        else
        {
            delete[]digestkey;

            MSG m;
            m.make_msg((uint8_t*)message_buffer, len);
            this->make_decrypt_msg(m, key, crc);
            return true;
        }
    }

    MSG::~MSG()
    {
        delete buffer;
        buffer = nullptr;
    }

}
