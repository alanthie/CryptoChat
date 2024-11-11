/*
 * Author: Alain Lanthier
 */
#ifndef NODEV4_H
#define NODEV4_H

#include "encrypt.h"
#include "random_engine.hpp"
#include "SHA256.h"
#include "IDEA.hpp"
#include <cstring>
#include <stdexcept>
#include <vector>

// cross platform
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
static WSAData wsaData;
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#endif

namespace ysSocket {

	constexpr bool DEBUG_INFO = false;
	constexpr int VERSION = 202411;

	const int MESSAGE_SIZE = 4 * 1024; // 4k or better if supported 64k to 8MB, use in recv(), send()

	// Make KEY_SIZE a multiple of 128 to support most encryption algos
	const int KEY_SIZE     = 2 * (1024 - 128); // Key transfer is encrypt and may 2x in size

	// History size
	const int HISTORY_SIZE = 10;

	const bool USE_BASE64_RND_KEY_GENERATOR = true;

	[[maybe_unused]] static std::string getDEFAULT_KEY()
	{
		return std::string("ertyewrtyewrt654tg45y66u57u68itik96807iedhywt21t521t2134t3tvgtt3561365121");
	}

	[[maybe_unused]] static std::string get_input_string()
	{
		std::string r;
		std::cin >> r;
		std::cin.ignore(10000, '\n');
		std::cin.clear();
		return r;
	}

	[[maybe_unused]] static long long str_to_ll(const std::string& snum)
	{
		long long r = -1;
		try
		{
			r = std::stoll(snum);
		}
		catch (...)
		{
			r = -1;
		}
		return r;
	}

	// UI
	struct netw_msg
	{
		bool is_receive;
		uint8_t msg_type;
		std::string msg;
	};

	enum class STATE {
		OPEN,
		CLOSED
	};

	const uint8_t MSG_EMPTY = 0;
	const uint8_t MSG_INVALID = 1;
	const uint8_t MSG_TEXT = 2;
	const uint8_t MSG_FILE = 3;
	const uint8_t MSG_CMD_REQU_KEY_HINT = 4;
	const uint8_t MSG_CMD_RESP_KEY_HINT = 5;
	const uint8_t MSG_CMD_INFO_KEY_VALID = 6;
	const uint8_t MSG_CMD_REQU_ACCEPT_RND_KEY = 7;
	const uint8_t MSG_CMD_RESP_ACCEPT_RND_KEY = 8;
	const uint8_t MSG_CMD_INFO_RND_KEY_VALID = 9;
	const uint8_t MSG_CMD_REQU_USERNAME = 10;
	const uint8_t MSG_CMD_RESP_USERNAME = 11;
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

		size_t size() { return buffer_len; };
		uint8_t* get_buffer()
		{
			return buffer;
		}

		std::string get_data_as_string()
		{
			if (buffer_len > 33)
				return std::string((char*)buffer + 33, buffer_len-33);
			return std::string{};
		}

		bool is_same(MSG& msgin)
		{
			if (this->type_msg != msgin.type_msg) return false;
			if (this->buffer_len != msgin.buffer_len) return false;
			if (memcmp(this->buffer,msgin.buffer,buffer_len)!=0) return false;
			return true;
		}


		void make_encrypt_msg(MSG& msgin, std::string& key)
		{
			std::vector<char> vmsgin(msgin.buffer_len - 33);
			for (size_t i = 33; i < msgin.buffer_len; i++) vmsgin[i-33] = msgin.buffer[i];
			std::string b64_str = Base64::encode(vmsgin);
			std::string s = encrypt_simple_string(b64_str, key);
			make_msg(msgin.type_msg, s, msgin.buffer+1);

			if (DEBUG_INFO)
				std::cout << "Encrypt ["
					+ get_summary_hex((char*)msgin.buffer+33, msgin.buffer_len - 33) + "]=>["
					+ get_summary_hex((char*)this->buffer + 33, this->buffer_len - 33)
					+ "]" << std::endl;
		}

		void make_decrypt_msg(MSG& msgin, std::string& key)
		{
			std::string s = msgin.get_data_as_string();
			std::string b64_encoded_str = decrypt_simple_string(s, key);
			std::vector<char> b64_decode_vec = Base64::decode(b64_encoded_str);

			buffer = new uint8_t[33 + b64_decode_vec.size()]{ 0 };
			buffer_len = 33 + (uint32_t)b64_decode_vec.size();
			buffer[0] = msgin.type_msg;
			type_msg = msgin.type_msg;
			for (size_t i = 0; i < b64_decode_vec.size(); i++) buffer[i+33] = b64_decode_vec[i];
			//memcpy(buffer + 1, digestkey, 32);
			memcpy(buffer + 1, msgin.buffer + 1, 32);

			if (DEBUG_INFO)
				std::cout << "Decrypt ["
				+ get_summary_hex((char*)msgin.buffer + 33, msgin.buffer_len - 33) + "]=>["
				+ get_summary_hex((char*)this->buffer + 33, this->buffer_len - 33)
				<< std::endl;
		}

		void make_msg(uint8_t t, const std::string& s, const std::string& key)
		{
			SHA256 sha;
			sha.update((uint8_t*)key.data(), key.size());
			uint8_t* digestkey = sha.digest();

			make_msg(t, s.size(), (uint8_t*)s.data(), digestkey);
			delete[]digestkey;
		}

		void make_msg(uint8_t t, uint32_t len_data, uint8_t* data, uint8_t* digestkey)
		{
			if (data == nullptr)
			{
				return;
			}

			type_msg = t;
			buffer_len = len_data + 33;
			buffer = new uint8_t[buffer_len]{ 0 };

			buffer[0] = t;
			memcpy(buffer + 1, digestkey, 32);
			memcpy(buffer+33, data, len_data);
		}

		void make_msg(uint8_t* buffer_in, size_t len)
		{
			if (buffer_in == nullptr)
			{
				return;
			}
			if (len == 0)
			{
				return;
			}

			buffer = new uint8_t[len]{ 0 };

			type_msg = buffer_in[0];
			buffer_len = (uint32_t)len;
			memcpy(buffer, buffer_in, len);
		}

		void make_msg(uint8_t t, const std::string& s, uint8_t* digestkey)
		{
			make_msg(t, (uint32_t)s.size(), (uint8_t*) s.data(), digestkey);
		}

		bool parse(char* message_buffer, size_t len, std::string key)
		{
			if (len < 33)
			{
				type_msg = MSG_EMPTY;
				std::cerr << "WARNING MSG_EMPTY in MSG::parse() msg_len = " << len << std::endl;
				return false;
			}

			if (key.size() == 0)
			{
				std::cerr << "WARNING KEY EMPTY in MSG::parse() " << std::endl;
				return false;
			}

			SHA256 sha;
			sha.update((uint8_t*)key.data(), key.size());
			uint8_t* digestkey = sha.digest();

			if (memcmp(message_buffer + 1, digestkey, 32) != 0)
			{
				std::cerr << "WARNING INVALID key digest in MSG::parse() " << std::endl;
			}
			delete[]digestkey;

			MSG m;
			m.make_msg( (uint8_t*)message_buffer, len);
			this->make_decrypt_msg(m, key);
			return true;
		}

		~MSG()
		{
			delete buffer;
			buffer = nullptr;
		}

		static bool encode_idea(cryptoAL::cryptodata& data_temp, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_temp_next)
		{
			bool r = true;
			char c;

			if (data_temp.buffer.size() % 8 != 0)
			{
				r = false;
				std::cerr << "ERROR " << "encode_idea data file must be multiple of 8 bytes idea: " << data_temp.buffer.size() << std::endl;
				return r;
			}
			if (data_temp.buffer.size() == 0)
			{
				r = false;
				std::cerr << "ERROR " << "encode_idea data file is empty " << std::endl;
				return r;
			}

			if (key_size % 16 != 0)
			{
				r = false;
				std::cerr << "ERROR " << "encode_idea key must be multiple of 16 bytes: " << key_size << std::endl;
				return r;
			}
			if (key_size == 0)
			{
				std::cerr << "ERROR encode_idea - key_size = 0 " << std::endl;
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

		static bool decode_idea(cryptoAL::cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_decrypted)
		{
			bool r = true;
			char c;

			if (key_size % 16 != 0)
			{
				r = false;
				std::cerr << "ERROR " << "decode_idea key must be multiple of 16 bytes " << key_size << std::endl;
				return r;
			}
			if (data_encrypted.buffer.size() % 8 != 0)
			{
				r = false;
				std::cerr << "ERROR " << "decode_idea data must be multiple of 8 bytes " << data_encrypted.buffer.size() << std::endl;
				return r;
			}
			if (key_size == 0)
			{
				std::cerr << "ERROR decode_sidea - key_size = 0 " << "" << std::endl;
				return false;
			}
			if (data_encrypted.buffer.size() == 0)
			{
				std::cerr << "ERROR decode_sidea - data file is empty " << std::endl;
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

	};

	class ysNodeV4 {
	protected:
		// Socket
		int m_socketFd = -1;
		struct sockaddr_in m_socketInfo;
		int m_port = 5000;
		int m_addressLen = 0;
		int m_messageSize = MESSAGE_SIZE;
		STATE m_state;

		// socket
		void setSocketInfo();
		void createSocket();
		void sendMessageBuffer(const int& t_socketFd, MSG& m, std::string key);
		//void sendMessageBuffer(const int& t_socketFd, uint8_t* t_message, size_t len, std::string key);
		void closeSocket();

	public:
		ysNodeV4();
		ysNodeV4(const int& t_port);

		// Port
		int getPort() const;
		void setPort(const int& t_port);

		// Socket file descriptor
		int getSocketFd() const;
		void setSocketFd(const int& t_socketFd);

		// Socket information
		sockaddr_in getSocketInfo() const;
		void setSocketInfo(const sockaddr_in& t_socketInfo);

		// Connection status
		STATE getState() const;
		void setState(const STATE& t_state);

		// Message size
		int getMessageSize() const;
		void setMessageSize(const int& t_messageSize);

		bool initial_key_validation_done = false;
		bool random_key_validation_done = false;

		std::string initial_key_hint;
		std::string initial_key;

		std::string random_key;
		//std::string previous_random_key;

		std::string pending_random_key;
		bool new_pending_random_key = false;

		std::string username;
		std::vector<netw_msg> vhistory;

		virtual ~ysNodeV4();
	};

}

#endif /* NODEV4_H */
