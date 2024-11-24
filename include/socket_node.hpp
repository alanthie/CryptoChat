/*
 * Author: Alain Lanthier
 */
#ifndef socket_node_H
#define socket_node_H

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
#include <atomic>

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

namespace crypto_socket {

	// TODO replace by dynamic verbose flag
	//constexpr bool DEBUG_INFO = false;

	constexpr int VERSION = 202411;

	[[maybe_unused]] static std::string getDEFAULT_KEY()
	{
		return std::string("ertyewrtyewrt654tg45y66u57u68itik96807iedhywt21t521t2134t3tvgtt3"); // 64x
	}

	enum class STATE {
		OPEN,
		CLOSED
	};


	class socket_node {
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

		int  sendMessageBuffer( const int& t_socketFd, NETW_MSG::MSG& m, std::string key,
                                uint8_t crypto_flag=0, uint8_t from_user=0, uint8_t to_user=0);
		void closeSocket(bool force = false);

	public:
		socket_node();
		socket_node(const int& t_port);

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

		std::map<int, std::mutex> _send_mutex; //...only one per socket... no map needed
		std::mutex& get_send_mutex(int sock)
		{
			return _send_mutex[sock]; // constructs it inside the map if doesn't exist
		}

		virtual ~socket_node();
	};


	class client_node : public socket_node
	{
	public:
		client_node() : socket_node()
		{
		}

		client_node(const int& t_port) : socket_node(t_port)
		{
		}

		int count_initial_key_validation = 0;
		bool initial_key_validation_done = false;
		bool random_key_validation_done = false;

		std::string initial_key_hint;
		std::string initial_key;
		std::string initial_key64;

		std::string previous_random_key;
		std::string random_key;
		std::string pending_random_key;
		bool new_pending_random_key = false;

		std::string username;
		std::string hostname;
		std::string machine_id;
		uint32_t user_index = 0; // invalid, unique user number like an ip 1 to ffffffff
	};

}

#endif
