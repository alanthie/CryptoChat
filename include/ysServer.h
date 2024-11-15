/*
 * Author: Alain Lanthier
 **
 */

#ifndef YSSERVER_H
#define YSSERVER_H

#include "ysNodeV4.h"
#include <vector>
#include <functional>
#include <algorithm>
#include <thread>
#include <mutex>

namespace ysSocket {

	class ysServer : protected ysNodeV4 {
	protected:
		void setDefault();

		// message event function
		std::function<void(const std::string& t_message) > m_onMessage = nullptr;
		void showMessage(const std::string& t_message);

		// One RECV thread per client
		std::vector<std::thread> v_thread;
		void joinThread();

		std::mutex m_mu; // showMessage lock

		// N clients
		int m_nodeSize = 0;
		std::vector<ysNodeV4*> v_client;
		void closeClient();

		// server
		//int m_connectionSize = 128;
		void createServer();
		void bindServer();
		void listenServer();
		bool check_default_encrypt(std::string& key);
		void set_key_hint();
		void handle_accept();

		// Message
		void sendMessageClients(const std::string& t_message);
		void sendMessageAll(const std::string& t_message, const int& t_socket);

		void sendMessageAll(NETW_MSG::MSG& msg, const int& t_socket);

	public:
		//ysServer();
		//ysServer(const int& t_port);
		//ysServer(const int& t_port, const int& t_connectionSize);
		ysServer(cryptochat::cfg::cfg_srv cfg);

		void setOnMessage(const std::function<void(const std::string&) >& t_function);

		void runServer();
		void closeServer();

		size_t get_client_index(const int& t_socket);
		void request_client_initial_key(const int& t_socket);
		void request_accept_rnd_key(const int& t_socket);

		cryptochat::cfg::cfg_srv _cfg;
		virtual ~ysServer();
	};

}

#endif /* YSSERVER_H */
