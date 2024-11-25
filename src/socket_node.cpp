/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <mutex>
#include "../include/socket_node.hpp"

namespace crypto_socket {

	void socket_node::setSocketInfo() {
		this->m_addressLen = sizeof (this->m_socketInfo);
		std::memset(&this->m_socketInfo, 0, this->m_addressLen);
		this->m_socketInfo.sin_family = AF_INET;
		this->m_socketInfo.sin_port = htons(this->m_port);
	}

	socket_node::socket_node()
	{
		setSocketInfo();
	}

	socket_node::socket_node(const int& t_port) : m_port(t_port)
	{
		setSocketInfo();
	}

	int socket_node::getPort() const {
		return m_port;
	}

	void socket_node::setPort(const int& t_port) {
		m_port = t_port;
		setSocketInfo();
	}

	int socket_node::getSocketFd() const {
		return m_socketFd;
	}

	void socket_node::setSocketFd(const int& t_socketFd) {
		m_socketFd = t_socketFd;
	}

	sockaddr_in socket_node::getSocketInfo() const {
		return m_socketInfo;
	}

	void socket_node::setSocketInfo(const sockaddr_in& t_socketInfo) {
		m_socketInfo = t_socketInfo;
	}

	int socket_node::getMessageSize() const {
		return m_messageSize;
	}

	STATE socket_node::getState() const {
		return m_state;
	}

	void socket_node::setState(const STATE& t_state) {
		m_state = t_state;
	}

	void socket_node::setMessageSize(const int& t_messageSize) {
		m_messageSize = t_messageSize;
	}

	void socket_node::createSocket() {

#ifdef _WIN32
		if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
			throw std::runtime_error("WSAStartup() failed");
		}
#endif

		this->m_socketFd = socket(AF_INET, SOCK_STREAM, 0);
		if (this->m_socketFd == -1) {
			throw std::runtime_error("could not create socket");
		}
		this->m_state = STATE::OPEN;
	}

	int socket_node::sendMessageBuffer( const int& t_socketFd, NETW_MSG::MSG& m, std::string key, std::stringstream& serr,
                                        uint8_t crypto_flag, uint8_t from_user, uint8_t to_user)
	{
		serr << "sendMessageBuffer - entry m.buffer_len " << m.buffer_len << "\n";

		int r = 0;
		NETW_MSG::MSG m2;
		//uint8_t original_flag = m.buffer[NETW_MSG::MESSAGE_FLAG_START];

		if (m2.make_encrypt_msg(m, key) == false)
		{
			// TODO...
			serr << "ERROR - make_encrypt_msg FAILED\n";
			return -1;
		}

		if (m2.buffer_len >= NETW_MSG::MESSAGE_SIZE)
		{
			serr << "WARNING - sending too much data\n";
			return -1;
		}

		serr << "sendMessageBuffer - after m2.buffer_len " << m2.buffer_len << "\n";

		uint32_t expected_len = NETW_MSG::MSG::byteToUInt4((char*)m2.buffer + 1);
		if (expected_len != m2.buffer_len)
		{
			serr << "ERROR - SEND  (expected_len != m2.buffer_len)" << std::endl;
			return -1;
		}

		m2.buffer[NETW_MSG::MESSAGE_FLAG_START] = crypto_flag;
		NETW_MSG::MSG::uint4ToByte(from_user, (char*)m2.buffer + NETW_MSG::MESSAGE_FROM_START);
		NETW_MSG::MSG::uint4ToByte(to_user,   (char*)m2.buffer + NETW_MSG::MESSAGE_TO_START);

		// LOCK
		std::lock_guard lck(get_send_mutex(t_socketFd));
		r = send(t_socketFd, (char*)m2.buffer, (int)m2.buffer_len, 0);

#ifdef _WIN32
		if (r == SOCKET_ERROR) {
			serr << "ERROR - send failed with error: %d\n", WSAGetLastError();
		}
		else if (r < m2.buffer_len)
		{
			serr << "WARNING - NOT all data send\n";

			int bytes_sent = r;
			while (bytes_sent < m2.buffer_len)
			{
				int bytes_s0 = send(t_socketFd, (char*)m2.buffer + bytes_sent, m2.buffer_len - bytes_sent, 0);

				if (bytes_s0 == SOCKET_ERROR) {
					serr << "ERROR - send failed with error: %d\n", WSAGetLastError();
					return SOCKET_ERROR;
				}

				bytes_sent += bytes_s0;
			}
			serr << "INFO - All data send\n";
		}
		else if (r == m2.buffer_len)
		{
		}
		else if (r > m2.buffer_len)
		{
			serr << "WARNING - Excess data send\n";
		}

#else
		if (r == -1)
		{
			serr << "ERROR - send failed with error: " << errno << " len:" << m2.buffer_len << "\n";
		}
		else if (r < (int)m2.buffer_len)
		{
			serr << "WARNING - NOT all data send from sendMessageBuffer\n";
		}
#endif
		return r;
	}

	void socket_node::closeSocket(bool force) {
		if (this->m_state == STATE::CLOSED && force==false) {
			return;
		}

#ifdef _WIN32
		std::cout << "closesocket " << this->m_socketFd  << std::endl;
		if (::closesocket(this->m_socketFd) < 0) {
            std::cout << "could not close socket" << std::endl;
			throw std::runtime_error("Could not close socket");
		}
		::WSACleanup();
#else
        std::cout << "shutdown socket" << std::endl;
		if (shutdown(this->m_socketFd, SHUT_RDWR) < 0) {
            std::cout << "could not shutdown socket" << std::endl;
			//throw std::runtime_error("Could not shutdown socket");
		}

		std::cout << "close socket" << std::endl;
		if (close(this->m_socketFd) < 0) {
            std::cout << "could not close socket" << std::endl;
			//throw std::runtime_error("Could not close socket");
		}
#endif
		this->m_state = STATE::CLOSED;
	}

	socket_node::~socket_node() {
        std::cout << "~socket_node" << std::endl;
	}
}
