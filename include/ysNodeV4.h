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

#include "../include/netw_msg.hpp"
//using namespace NETW_MSG;


namespace ysSocket {

	constexpr bool DEBUG_INFO = false;
	constexpr int VERSION = 202411;

	const int MESSAGE_SIZE = 4 * 1024; // 4k or better if supported 64k to 8MB, use in recv(), send()

	// Make KEY_SIZE a multiple of 128 to support most encryption algos
	const int KEY_SIZE     = 2 * (1024 - 128); // Key transfer is encrypt and may 2x in size

	// History size
	const int HISTORY_SIZE = 20;

	const bool USE_BASE64_RND_KEY_GENERATOR = true;
	//AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // vigenere BUG

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
		int m_messageSize = MESSAGE_SIZE;
		STATE m_state;

		// socket
		void setSocketInfo();
		void createSocket();
		void sendMessageBuffer(const int& t_socketFd, NETW_MSG::MSG& m, std::string key);
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

		std::string random_key;
		//std::string previous_random_key;

		std::string pending_random_key;
		bool new_pending_random_key = false;

		std::string username;
		std::vector<NETW_MSG::netw_msg> vhistory;

		virtual ~ysNodeV4();
	};

}

#endif /* NODEV4_H */
