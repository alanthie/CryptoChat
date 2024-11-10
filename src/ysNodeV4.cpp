/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include "../include/ysNodeV4.h"

namespace ysSocket {

	void ysNodeV4::setSocketInfo() {
		this->m_addressLen = sizeof (this->m_socketInfo);
		std::memset(&this->m_socketInfo, 0, this->m_addressLen);
		this->m_socketInfo.sin_family = AF_INET;
		this->m_socketInfo.sin_port = htons(this->m_port);
	}

	ysNodeV4::ysNodeV4() {
		setSocketInfo();
	}

	ysNodeV4::ysNodeV4(const int& t_port) :
	m_port(t_port) {
		setSocketInfo();
	}

	int ysNodeV4::getPort() const {
		return m_port;
	}

	void ysNodeV4::setPort(const int& t_port) {
		m_port = t_port;
		setSocketInfo();
	}

	int ysNodeV4::getSocketFd() const {
		return m_socketFd;
	}

	void ysNodeV4::setSocketFd(const int& t_socketFd) {
		m_socketFd = t_socketFd;
	}

	sockaddr_in ysNodeV4::getSocketInfo() const {
		return m_socketInfo;
	}

	void ysNodeV4::setSocketInfo(const sockaddr_in& t_socketInfo) {
		m_socketInfo = t_socketInfo;
	}

	int ysNodeV4::getMessageSize() const {
		return m_messageSize;
	}

	STATE ysNodeV4::getState() const {
		return m_state;
	}

	void ysNodeV4::setState(const STATE& t_state) {
		m_state = t_state;
	}

	void ysNodeV4::setMessageSize(const int& t_messageSize) {
		m_messageSize = t_messageSize;
	}

	void ysNodeV4::createSocket() {

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
//
//	void ysNodeV4::sendMessage(const int& t_socketFd, const std::string& t_message) 
//	{
//		int r = send(t_socketFd, t_message.c_str(), t_message.size(), 0);
//
//#ifdef _WIN32
//		if (r == SOCKET_ERROR) {
//			std::cout << "send failed with error: %d\n", WSAGetLastError();
//		}
//#else
//		if (r == -1) {
//			std::cout << "send failed with error: %d\n", errno());
//		}
//#endif
//	}

	void ysNodeV4::sendMessageBuffer(const int& t_socketFd, MSG& m, std::string key)
	{
		MSG m2;
		m2.make_encrypt_msg(m, key);

		if (m2.buffer_len >= MESSAGE_SIZE)
		{
			std::cout << "WARNING - sending too much data in send from sendMessageBuffer\n";
		}

		int r = send(t_socketFd, (char*)m2.buffer, (int)m2.buffer_len, 0);

#ifdef _WIN32
		if (r == SOCKET_ERROR) {
			std::cout << "ERROR - send failed with error: %d\n", WSAGetLastError();
		}
		else if (r < m2.buffer_len)
		{
			std::cout << "WARNING - bot all data send from sendMessageBuffer\n";
		}

#else
		if (r == -1)
		{
			std::cout << "ERROR - send failed with error: %d\n", errno());
		}
		else if (r < m2.buffer_len)
		{
			std::cout << "WARNING - not all data send from sendMessageBuffer\n");
		}
#endif
	}

//	void ysNodeV4::sendMessageBuffer(const int& t_socketFd, uint8_t* t_message, size_t len)
//	{
//		//if (key.size() == 0)
//		//{
//		//	std::cerr << "KEY EMPTY in sendMessageBuffer() " << std::endl;
//		//}
//
//		MSG m, m2;
//		m.make_msg(t_message, len);
//		m2.make_encrypt_msg(m, key);
//
//		//int r = send(t_socketFd, (char*)t_message, (int)len, 0);
//		int r = send(t_socketFd, (char*)m2.buffer, (int)m2.buffer_len, 0);
//
//#ifdef _WIN32
//		if (r == SOCKET_ERROR) {
//			std::cout << "send failed with error: %d\n", WSAGetLastError();
//		}
//#else
//		if (r == -1) {
//			std::cout << "send failed with error: %d\n", errno());
//		}
//#endif
//	}

	void ysNodeV4::closeSocket() {
		if (this->m_state == STATE::CLOSED) {
			return;
		}
#ifdef _WIN32
		if (::closesocket(this->m_socketFd) < 0) {
			throw std::runtime_error("Could not close socket");
		}
		::WSACleanup();
#else
		if (close(this->m_socketFd) < 0) {
			throw std::runtime_error("Could not close socket");
		}
#endif
		this->m_state = STATE::CLOSED;
	}

	ysNodeV4::~ysNodeV4() {
		closeSocket();
	}

}