/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <mutex>
#include "../include/ysNodeV4.h"

namespace ysSocket {

	void ysNodeV4::setSocketInfo() {
		this->m_addressLen = sizeof (this->m_socketInfo);
		std::memset(&this->m_socketInfo, 0, this->m_addressLen);
		this->m_socketInfo.sin_family = AF_INET;
		this->m_socketInfo.sin_port = htons(this->m_port);
	}

	ysNodeV4::ysNodeV4()
	{
		setSocketInfo();
	}

	ysNodeV4::ysNodeV4(const int& t_port) : m_port(t_port)
	{
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

	int ysNodeV4::sendMessageBuffer(const int& t_socketFd, NETW_MSG::MSG& m, std::string key)
	{
		int r = 0;
		NETW_MSG::MSG m2;
		m2.make_encrypt_msg(m, key);

		if (m2.buffer_len >= NETW_MSG::MESSAGE_SIZE)
		{
			std::cerr << "WARNING - sending too much data\n";
		}

		uint32_t expected_len = NETW_MSG::MSG::byteToUInt4((char*)m2.buffer + 1);
		if (expected_len != m2.buffer_len)
		{
			std::cerr << "ERROR - SEND  (expected_len != m2.buffer_len)" << std::endl;
		}

		// LOCK
		std::lock_guard lck(get_send_mutex(t_socketFd));
		r = send(t_socketFd, (char*)m2.buffer, (int)m2.buffer_len, 0);

		//std::cout << "SEND(), expected:" << (int)m2.buffer_len << " r:" << r << std::endl ;

#ifdef _WIN32
		if (r == SOCKET_ERROR) {
			std::cerr << "ERROR - send failed with error: %d\n", WSAGetLastError();
		}
		else if (r < m2.buffer_len)
		{
			std::cerr << "WARNING - NOT all data send\n";

			int bytes_sent = r;
			while (bytes_sent < m2.buffer_len)
			{
				int bytes_s0 = send(t_socketFd, (char*)m2.buffer + bytes_sent, m2.buffer_len - bytes_sent, 0);

				if (bytes_s0 == SOCKET_ERROR) {
					std::cerr << "ERROR - send failed with error: %d\n", WSAGetLastError();
					return SOCKET_ERROR;
				}

				bytes_sent += bytes_s0;
			}
			std::cerr << "INFO - All data send\n";
		}
		else if (r == m2.buffer_len)
		{
		}
		else if (r > m2.buffer_len)
		{
			std::cerr << "WARNING - Excess data send\n";
		}

#else
		if (r == -1)
		{
			std::cerr << "ERROR - send failed with error: " << errno << "\n";
		}
		else if (r < (int)m2.buffer_len)
		{
			std::cerr << "WARNING - NOT all data send from sendMessageBuffer\n";
		}
#endif
		return r;
	}

	void ysNodeV4::closeSocket(bool force) {
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
			throw std::runtime_error("Could not shutdown socket");
		}

		if (close(this->m_socketFd) < 0) {
            std::cout << "could not close socket" << std::endl;
			throw std::runtime_error("Could not close socket");
		}
#endif
		this->m_state = STATE::CLOSED;
	}

	ysNodeV4::~ysNodeV4() {
        std::cout << "~ysNodeV4" << std::endl;
		closeSocket(true);
	}

	bool ysNodeV4::add_file_to_send(const std::string& filename, const std::string& filename_key)
	{
		std::lock_guard lck(_map_file_to_send_mutex);
		if (!map_file_to_send.contains(filename_key))
		{
			map_file_to_send[filename_key] = NETW_MSG::MSG_BINFILE();

			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_key];
			binfile.init(filename, filename_key, true);

			ui_dirty = true;
			return true;
		}
		return true; // already exist
	}
	bool ysNodeV4::add_file_to_recv(const std::string& filename, const std::string& filename_key)
	{
		std::lock_guard lck(_map_file_to_recv_mutex);
		if (!map_file_to_recv.contains(filename_key))
		{
			map_file_to_recv[filename_key] = NETW_MSG::MSG_BINFILE();

			NETW_MSG::MSG_BINFILE& binfile = map_file_to_recv[filename_key];
			binfile.init(filename, filename_key, false);

			ui_dirty = true;
			return true;
		}
		return true; // already exist
	}

	bool ysNodeV4::get_info_file_to_send(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done)
	{
		std::lock_guard lck(_map_file_to_send_mutex);
		if (map_file_to_send.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_key];
			byte_processed = binfile.byte_send;
			total_size = binfile.data_size_in_fragments();
			is_done = binfile._is_processing_done;
			return true;
		}
		return false;
	}
	bool ysNodeV4::get_info_file_to_recv(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done)
	{
		std::lock_guard lck(_map_file_to_recv_mutex);
		if (map_file_to_recv.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_recv[filename_key];
			byte_processed = binfile.byte_recv;
			//total_size = binfile.data_size_in_fragments();
			total_size = binfile.total_size_read_from_fragment;
			is_done = binfile._is_processing_done;
			return true;
		}
		return false;
	}

	std::string ysNodeV4::get_file_to_send(const std::string& filename_key)
	{
		std::string r;
		std::lock_guard lck(_map_file_to_send_mutex);
		if (map_file_to_send.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_key];
			if (binfile._file != nullptr)
			{
				r = std::string(binfile._file->buffer.getdata(), binfile._file->buffer.size());
			}
		}
		return r;
	}
	std::string ysNodeV4::get_file_to_recv(const std::string& filename_key)
	{
		std::string r;
		std::lock_guard lck(_map_file_to_recv_mutex);
		if (map_file_to_recv.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_recv[filename_key];
			if (binfile._file != nullptr)
			{
				r = std::string(binfile._file->buffer.getdata(), binfile._file->buffer.size());
			}
		}
		return r;
	}

	bool ysNodeV4::send_next_pending_file_packet(const int& t_socketFd, const std::string& key, int& send_status)
	{
		send_status = 0;
		bool msg_sent = false;

		std::string filename_with_pending_processing;
		{
			std::lock_guard lck(_map_file_to_send_mutex);

			if (map_file_to_send.size() == 0)
				return false;

			for (auto& [filename, binfile] : map_file_to_send)
			{
				if (binfile.has_unprocess_fragment())
				{
					filename_with_pending_processing = filename;
					break;
				}
			}
		}

		if (filename_with_pending_processing.size() > 0)
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_with_pending_processing];
			NETW_MSG::MSG m;
			bool r = m.make_next_file_fragment_to_send(binfile, key, true);
			if (r)
			{
				send_status = sendMessageBuffer(t_socketFd, m, key);
				msg_sent = true;
				ui_dirty = true;
			}
		}

		// delete file done and not in history....


		return msg_sent;
	}
}
