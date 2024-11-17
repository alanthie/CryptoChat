/*
 * Author: Alain Lanthier
 */
#ifndef NODEV4_H
#define NODEV4_H

#include "encrypt.h"
#include "random_engine.hpp"
#include "../include/netw_msg.hpp"
#include "../include/cfg_srv.hpp"
#include "SHA256.h"
#include "IDEA.hpp"
#include <cstring>
#include <stdexcept>
#include <vector>
#include <map>
#include <queue>
#include <mutex>


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

#include "../include/netw_msg.hpp"
//using namespace NETW_MSG;


namespace ysSocket {

	//constexpr bool DEBUG_INFO = false;
	constexpr int VERSION = 202411;

	//const int MESSAGE_SIZE = 4 * 1024; // 4k or better if supported 64k to 8MB, use in recv(), send()

	// Make KEY_SIZE a multiple of 128 to support most encryption algos
	//const int KEY_SIZE     = 2 * (1024 - 128); // Key transfer is encrypt and may 2x in size

	// UI history size
	const int HISTORY_SIZE = 2000;

	const bool USE_BASE64_RND_KEY_GENERATOR = true;
	//AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "; // vigenere BUG

	[[maybe_unused]] static std::string getDEFAULT_KEY()
	{
		return std::string("ertyewrtyewrt654tg45y66u57u68itik96807iedhywt21t521t2134t3tvgtt3561365121");
	}

	enum class STATE {
		OPEN,
		CLOSED
	};


	class ysNodeV4 {
	protected:
		// Socket
		int m_socketFd = -1;
		struct sockaddr_in m_socketInfo;
		int m_port = 5000;
		int m_addressLen = 0;
		int m_messageSize = NETW_MSG::MESSAGE_SIZE;
		STATE m_state;

		// socket
		void setSocketInfo();
		void createSocket();
		int sendMessageBuffer(const int& t_socketFd, NETW_MSG::MSG& m, std::string key);
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

		int challenge_attempt = 0;
		std::string initial_key_hint;
		std::string initial_key;

		std::string previous_random_key;
		std::string random_key;
		std::string pending_random_key;
		bool new_pending_random_key = false;

		std::string username;
		std::string hostname;
		size_t history_cnt = 0;
		std::vector<NETW_MSG::netw_msg> vhistory;

		std::map<int, std::mutex> _send_mutex; //...only one per socket... no map needed
		std::mutex& get_send_mutex(int sock)
		{
			return _send_mutex[sock]; // constructs it inside the map if doesn't exist
		}

		std::map<std::string, NETW_MSG::MSG_BINFILE> map_file_to_send;
		std::map<std::string, NETW_MSG::MSG_BINFILE> map_file_to_recv;

		std::mutex _map_file_to_send_mutex;
		std::mutex _map_file_to_recv_mutex;

		std::atomic<bool> ui_dirty = true;

		bool add_file_to_send(const std::string& filename, const std::string& filename_key);
		bool add_file_to_recv(const std::string& filename, const std::string& filename_key);
		//bool add_msg_to_send(const NETW_MSG::MSG& m);
		//bool add_msg_to_recv(const NETW_MSG::MSG& m);

		bool get_info_file_to_send(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done);
		bool get_info_file_to_recv(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done);

		std::string get_file_to_send(const std::string& filename_key);
		std::string get_file_to_recv(const std::string& filename_key);

		bool send_next_pending_file_packet(const int& t_socketFd, const std::string& key, int& send_status);

		virtual ~ysNodeV4();
	};

}

#endif /* NODEV4_H */
