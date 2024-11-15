/*
 * Author: Alain Lanthier
 */

#ifndef YSCLIENT_H
#define YSCLIENT_H

#include "ysNodeV4.h"
#include "cfg_cli.hpp"
#include <iostream>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

namespace ysSocket {

	class ysClient : protected ysNodeV4
	{
	protected:
		void setDefault();
		std::string get_input(const std::string& q);

		// message event function
		std::function<void(const std::string& t_message) > m_onMessage = nullptr;
		void showMessage(const std::string& t_message);

		// server
		std::string m_serverName = "localhost";

		// thread
		std::thread m_recv_thread; // RECV thread
		std::thread m_send_thread; // SEND thread to handle all send...

		void _connectServer();

    public:
		void recv_thread();
		void send_pending_file_packet_thread();
		void client_UI(); // main THREAD

		std::mutex _key_mutex;
		std::mutex _vhistory_mutex;
		bool key_valid = false;
		bool rnd_valid = false;
		bool user_valid = false;
		std::atomic<bool> input_interrupted = false;

        cryptochat::cfg::cfg_cli    _cfg_cli;
        const std::string&          _cfgfile;

	public:
//		ysClient();
		ysClient(cryptochat::cfg::cfg_cli cfg, const std::string& cfgfile);
//		ysClient(const int& t_port);
//		ysClient(const std::string& t_serverName, const int& t_port);

		void setOnMessage(const std::function<void(const std::string&) >& t_function);

		void connectServer();
		void closeConnection();

		std::string get_DEFAULT_KEY() { return getDEFAULT_KEY(); }
		std::string get_initial_key() { return initial_key; }
		std::string get_random_key()  { return random_key; }

		int send_message_buffer(const int& t_socketFd, NETW_MSG::MSG& m, std::string key)
		{
			return sendMessageBuffer(t_socketFd, m, key);
		}

		int get_socket() { return m_socketFd; }

		std::vector<NETW_MSG::netw_msg> get_vhistory()
		{
			// copy between threads
			std::lock_guard l(_vhistory_mutex);// recursive mutex deadlock to watch for
			return vhistory;
		}

		void add_to_history(bool is_receive, uint8_t msg_type, std::string& msg, std::string filename = {}, bool is_for_display = true)
		{
			std::lock_guard l(_vhistory_mutex);// recursive mutex deadlock to watch for
			vhistory.push_back({ is_receive, msg_type, msg, filename, is_for_display, {} });
			while (vhistory.size() > HISTORY_SIZE)
			{
				vhistory.erase(vhistory.begin());
			}
		}

		bool add_file_to_send(const std::string& filename) {
			return ysNodeV4::add_file_to_send(filename);
		}
		bool add_file_to_recv(const std::string& filename)
		{
			return ysNodeV4::add_file_to_recv(filename);
		}

		bool get_info_file_to_send(const std::string& filename, size_t& byte_processed, size_t& total_size, bool& is_done)
		{
			return ysNodeV4::get_info_file_to_send(filename, byte_processed, total_size, is_done);
		}
		bool get_info_file_to_recv(const std::string& filename, size_t& byte_processed, size_t& total_size, bool& is_done)
		{
			return ysNodeV4::get_info_file_to_recv(filename, byte_processed, total_size, is_done);
		}

		std::string get_file_to_send(const std::string& filename)
		{
			return ysNodeV4::get_file_to_send(filename);
		}
		std::string get_file_to_recv(const std::string& filename)
		{
			return ysNodeV4::get_file_to_recv(filename);
		}

		bool send_next_pending_file_packet(const int& t_socketFd, const std::string& key, int& send_status)
		{
			return ysNodeV4::send_next_pending_file_packet(t_socketFd, key, send_status);
		}

		virtual ~ysClient();
	};

}

#endif /* YSCLIENT_H */
