/*
 * Author: Alain Lanthier
 */

#ifndef YSCLIENT_H
#define YSCLIENT_H

#include "ysNodeV4.h"
#include <iostream>
#include <functional>
#include <thread>
#include <mutex>

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
		std::thread m_thread;
		std::mutex m_mu;

		void _connectServer();

    public:
		void receiveMessage();
		void writeMessage();

		std::mutex _mutex;
		bool key_valid = false;
		bool rnd_valid = false;
		bool user_valid = false;

	public:
		ysClient();
		ysClient(const int& t_port);
		ysClient(const std::string& t_serverName, const int& t_port);

		void setOnMessage(const std::function<void(const std::string&) >& t_function);

		void connectServer();
		void closeConnection();

		std::string get_DEFAULT_KEY() { return getDEFAULT_KEY(); }
		std::string get_initial_key() { return initial_key; }
		std::string get_random_key() { return random_key; }
		void send_message_uffer(const int& t_socketFd, MSG& m, std::string key) {
			sendMessageBuffer(t_socketFd, m, key);
		}
		int get_socket() { return m_socketFd; }
		std::vector<netw_msg> get_vhistory()
		{
			// copy between threads
			std::lock_guard l(_mutex);// recursive mutex deadlock to watch for
			return vhistory;
		}

		void add_to_history(bool is_receive, uint8_t msg_type, std::string& msg)
		{
			std::lock_guard l(_mutex);// recursive mutex deadlock to watch for
			vhistory.push_back({ is_receive, msg_type, msg });
			while (vhistory.size() > HISTORY_SIZE)
			{
				vhistory.erase(vhistory.begin());
			}
		}

		virtual ~ysClient();
	};

}

#endif /* YSCLIENT_H */
