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

// TODO
//	ysNodeV4 ==> base_socket (only common socket functions)
//  client : base_socket + client specifics
//	server : base_socket + server specifics
//	chat_client main() cryptochat::cli::chat_cli(cfg).run() // chat_cli handle a client
//	chat_server main() cryptochat::srv::chat_srv(cfg).run() // chat_cli handle a server

namespace ysSocket
{
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
		std::mutex vclient_mutex;
		std::vector<ysNodeV4*> v_client;
		void closeClient();

		void handle_new_client(ysNodeV4* new_client);
		void handle_remove_client();
		void handle_info_client(const int& t_socket, bool send_to_current_user_only = false);

		// server
		void createServer();
		void bindServer();
		void listenServer();
		void set_key_hint();
		void handle_accept();

		void server_test();
		bool check_default_encrypt(std::string& key);
		bool check_idea_encrypt(std::string& key);
		bool check_salsa_encrypt(std::string& key);

		// Message
		void sendMessageClients(const std::string& t_message);

		void sendMessageAll(const std::string& t_message, const int& t_socket);
		void sendMessageAll(const std::string& t_message, const int& t_socket, uint8_t msg_type);
		void sendMessageAll(NETW_MSG::MSG& msg, const int& t_socket);
		void sendMessageOne(const std::string& t_message, const int& t_socket, uint8_t msg_type);

	public:
		ysServer(cryptochat::cfg::cfg_srv cfg);

		void setOnMessage(const std::function<void(const std::string&) >& t_function);

		void runServer();
		void closeServer();

		void request_client_initial_key(ysNodeV4* client);
		void request_accept_rnd_key(ysNodeV4* client);

		void close_client(ysNodeV4* client, bool force = false);

		cryptochat::cfg::cfg_srv _cfg;
		virtual ~ysServer();
	};

}

#endif /* YSSERVER_H */
