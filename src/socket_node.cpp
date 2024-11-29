/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <mutex>
#include "../include/base_const.hpp"
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

	int socket_node::send_composite(const int& t_socketFd, NETW_MSG::MSG& m, std::string key,
									std::stringstream& serr,
									uint8_t crypto_flag, uint8_t from_user, uint8_t to_user)
	{
		//cryptoAL::VERBOSE_DEBUG = 1;

		int r = 0;
		if (cryptoAL::VERBOSE_DEBUG)
			serr << std::endl << "send_composite" << std::endl;

		//... TODO ...
		//uint32_t	buffer_extra_len = 0;
		//uint8_t	buffer_extra[NETW_MSG::MESSAGE_SIZE + 1];

		// chat layer first
		NETW_MSG::MSG m2;
		if (m2.make_encrypt_msg(m, key, crypto_flag, from_user, to_user, serr) == false)
		{
			serr << "ERROR - send_composite - make_encrypt_msg FAILED\n";
			return -1;
		}

		if (cryptoAL::VERBOSE_DEBUG)
			serr << "send_composite - msg encrypted by chat layer, new len:" << m2.buffer_len << std::endl;

		uint32_t expected_len = NETW_MSG::MSG::byteToUInt4((char*)m2.buffer + 1);
		if (expected_len != m2.buffer_len)
		{
			serr << "ERROR - send_composite - (expected_len != m2.buffer_len)" << std::endl;
			return -1;
		}

		if (m2.buffer_len <= NETW_MSG::MESSAGE_SIZE)
		{
			if (cryptoAL::VERBOSE_DEBUG)
				serr << "send_composite - sending single packet, len= " << m2.buffer_len <<std::endl;
			return send_packet(t_socketFd, m2.buffer, m2.buffer_len, serr);
		}

		if (cryptoAL::VERBOSE_DEBUG)
			serr << "send_composite - multi packet message" << std::endl;

		uint32_t bytes_sent = 0;
		uint32_t bytes_to_send = 0;

		while (bytes_sent < m2.buffer_len)
		{
			bytes_to_send = m2.buffer_len - bytes_sent;
			if (bytes_to_send > NETW_MSG::MESSAGE_SIZE)
				bytes_to_send = NETW_MSG::MESSAGE_SIZE;

			// Blocking
			if (cryptoAL::VERBOSE_DEBUG)
				serr << "send_composite - sending a packet, len= " << bytes_to_send << std::endl;

			int bytes_s0 = send_packet(t_socketFd, m2.buffer + bytes_sent, bytes_to_send, serr);

#ifdef _WIN32
			if (bytes_s0 == SOCKET_ERROR)
			{
				serr << "ERROR - send failed with error: " << WSAGetLastError();
				return SOCKET_ERROR;
			}
#else
			if (bytes_s0 == -1)
			{
				serr << "ERROR - send failed with error: " << errno << "\n";
				return -1;
			}
#endif
			bytes_sent += bytes_s0;
		}

		if (bytes_sent > m2.buffer_len)
		{
			//... TODO ...
			serr << "WARNING - send excess data " << m2.buffer_len - bytes_sent << "\n";
			return -1;

			// keep extra
			//buffer_extra_len = m2.buffer_len - bytes_sent;
			//if (buffer_extra_len <= NETW_MSG::MESSAGE_SIZE)
			//{
			//	memcpy(buffer_extra, m2.buffer + bytes_sent, buffer_extra_len);
			//}
			//else
			//{
			//	serr << "ERROR - send_composite - (excess data sent > MESSAGE_SIZE " << buffer_extra_len << std::endl;
			//	return -1;
			//}
		}
		else
		{
			//buffer_extra_len = 0;
		}
		return m2.buffer_len;
	}

	int socket_node::send_packet(const int& t_socketFd, uint8_t* buffer, uint32_t buffer_len, std::stringstream& serr)
	{
		int r = 0;
		if (buffer_len > NETW_MSG::MESSAGE_SIZE)
		{
			serr << "ERROR - send_packet - sending too much data\n";
			return -1;
		}

		// LOCK
		{
			std::lock_guard lck(get_send_mutex(t_socketFd));
			r = send(t_socketFd, (char*)buffer, (int)buffer_len, 0);
		}

#ifdef _WIN32
		if (r == SOCKET_ERROR)
		{
			serr << "ERROR - send failed with error: " << WSAGetLastError() << "\n";
		}
#else
		if (r == -1)
		{
			serr << "ERROR - send failed with error: " << errno << "\n";
		}
#endif
		else if (r < buffer_len)
		{
			int bytes_sent = r;
			while (bytes_sent < buffer_len)
			{
				int bytes_s0 = send(t_socketFd, (char*)buffer + bytes_sent, buffer_len - bytes_sent, 0);
#ifdef _WIN32
				if (bytes_s0 == SOCKET_ERROR)
				{
					serr << "ERROR - send failed with error: " << WSAGetLastError() << "\n";
					return SOCKET_ERROR;
				}
#else
				if (bytes_s0 == -1)
				{
					serr << "ERROR - send failed with error: " << errno << "\n";
					return -1;
				}
#endif
				bytes_sent += bytes_s0;
			}
		}
		else if (r == buffer_len)
		{
		}
		else if (r > buffer_len)
		{
		}

		return r;
	}

	void socket_node::closeSocket(bool force)
	{
		if (this->m_state == STATE::CLOSED && force==false)
		{
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
