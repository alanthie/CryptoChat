#ifndef NETWMSG_H
#define NETWMSG_H

#include <cstring>
#include <stdexcept>
#include <string>
#include "encrypt.h"
#include "random_engine.hpp"
#include "SHA256.h"
#include "IDEA.hpp"

namespace NETW_MSG
{

struct netw_msg
{
	bool is_receive;
	uint8_t msg_type;
	std::string msg;
};

const uint8_t MSG_EMPTY = 0;
const uint8_t MSG_INVALID = 1;
const uint8_t MSG_TEXT = 2;
const uint8_t MSG_FILE = 3;
const uint8_t MSG_CMD_REQU_KEY_HINT = 4;
const uint8_t MSG_CMD_RESP_KEY_HINT = 5;
const uint8_t MSG_CMD_INFO_KEY_VALID = 6;
const uint8_t MSG_CMD_INFO_KEY_INVALID = 7;
const uint8_t MSG_CMD_REQU_ACCEPT_RND_KEY = 10;
const uint8_t MSG_CMD_RESP_ACCEPT_RND_KEY = 11;
const uint8_t MSG_CMD_INFO_RND_KEY_VALID = 12;
const uint8_t MSG_CMD_REQU_USERNAME = 20;
const uint8_t MSG_CMD_RESP_USERNAME = 21;
//
const uint8_t MSG_FILE_FRAGMENT = 128;

struct MSG_FILE_FRAGMENT_HEADER
{
	std::string filename;
	std::string total_size;
	std::string from;
	std::string to;

	size_t header_size()
	{
		return make_header().size();
	}
	std::string make_header()
	{
		return "[" + filename + "," + total_size + "," + from + "," + to + "]";
	}

	size_t get_pos_delimiter(size_t pos_start, const std::string& data, char delim)
	{
		for (size_t p = pos_start; p < data.size() - pos_start; p++)
		{
			if (data[p] == delim) return p;
		}
		return 0;
	}

	std::string get_substr(size_t pos_start, size_t pos_end, const std::string& data)
	{
		return data.substr(pos_start, pos_end - pos_start + 1);
	}

	bool parse_header(const std::string& data)
	{
		size_t sz = header_size();
		if (data.size() < sz) return false;
		size_t pos_file = 1;
		size_t pos_total_size = 1 + get_pos_delimiter(pos_file, data, ',');
		size_t pos_from = 1 + get_pos_delimiter(pos_total_size, data, ',');
		size_t pos_to = 1 + get_pos_delimiter(pos_from, data, ',');
		size_t end_bracket = 1 + get_pos_delimiter(pos_to, data, ']');

		filename = get_substr(pos_file, pos_total_size - 2, data);
		total_size = get_substr(pos_total_size, pos_from - 2, data);
		from = get_substr(pos_from, pos_to - 2, data);
		to = get_substr(pos_to, pos_to - end_bracket, data);

		return true;
	}
};

struct MSG
{
	uint8_t type_msg = MSG_EMPTY; // buffer[0]
	// digest of key = buffer[1]...buffer[32]

	uint32_t buffer_len = 0;
	uint8_t* buffer = nullptr;


	size_t size();
	uint8_t* get_buffer();

	std::string get_data_as_string();
	bool is_same(MSG& msgin);

	void make_encrypt_msg(MSG& msgin, std::string& key);
	void make_decrypt_msg(MSG& msgin, std::string& key);
	void make_msg(uint8_t t, const std::string& s, const std::string& key);
	void make_msg(uint8_t t, uint32_t len_data, uint8_t* data, uint8_t* digestkey);
	void make_msg(uint8_t* buffer_in, size_t len);
	void make_msg(uint8_t t, const std::string& s, uint8_t* digestkey);
	bool parse(char* message_buffer, size_t len, std::string key);

	~MSG();

	static bool encode_idea(cryptoAL::cryptodata& data_temp, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_temp_next);
	static bool decode_idea(cryptoAL::cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_decrypted);

	static std::vector<std::string> split(std::string& s, const std::string& delimiter) ;
};

}

#endif
