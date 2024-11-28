/*
 * Author: Alain Lanthier
 */

#include "../include/challenge.hpp"
#include "../include/crc32a.hpp"
#include "../include/SHA256.h"
#include "../include/crypto_server.hpp"
#include "../include/file_util.hpp"
#include "../include/encdec_algo.hpp"
#include <iostream>
#include <string>

#ifdef _WIN32
#pragma warning(disable : 4996)
#endif

namespace crypto_socket {

	void crypto_server::setDefault() {
		this->m_socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	void crypto_server::showMessage(const std::string& t_message) {
		if (this->m_onMessage != nullptr) {
			std::lock_guard<std::mutex> locker(this->m_mu);
			this->m_onMessage(t_message);
		}
	}

	crypto_server::crypto_server(cryptochat::cfg::cfg_srv cfg) :
		socket_node(cfg._port),
		_cfg(cfg)
	{
		setDefault();
	}


	void crypto_server::setOnMessage(const std::function<void(const std::string&)>& t_function) {
		m_onMessage = t_function;
	}

	void crypto_server::runServer()
	{
		read_map_machineid_to_user_index();

		this->createServer();
		this->bindServer();
		this->listenServer();

        server_test();

        if (USE_BASE64_RND_KEY_GENERATOR == false)
			first_pending_random_key = cryptoAL::random::generate_base10_random_string(NETW_MSG::KEY_SIZE);
        else
			first_pending_random_key = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

		this->set_key_hint();
		this->handle_accept();
	}

	void crypto_server::set_key_hint()
	{
		if (_cfg._map_challenges.size() > 0)
		{
			// TODO pick one at random...
			auto iter = _cfg._map_challenges.begin();
			initial_key_hint = iter->first;
			initial_key = iter->second;
			initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());

			std::cout << std::endl;
			std::cout << "INFO initial challenge set to : " << std::endl;
			_cfg.print_challenge(initial_key_hint, iter->second);
			std::cout << std::endl;
		}
		else
		{
			// TODO ask user...
			//
			// For KEYS: cryptoAL_vigenere::AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
			initial_key_hint = "1th prime number\n1000th prime number";
			initial_key = "27919";
			initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
		}
	}

	void crypto_server::createServer() {
		const int opt = 1;
		this->createSocket();
		if (setsockopt(this->m_socketFd, SOL_SOCKET, SO_REUSEADDR, (const char*) &opt, sizeof (opt))) {
			throw std::runtime_error("setsockopt");
		}
	}

	void crypto_server::bindServer()
	{
		if (bind(this->m_socketFd, reinterpret_cast<sockaddr*> (&this->m_socketInfo), this->m_addressLen) == -1)
		{
            std::string serr;
#ifdef _WIN32
#else
            int r = errno;
            serr = std::to_string(r) + " ";
            if (r == EACCES) serr = "EACCES";
            else if (r == EADDRINUSE) serr = "EADDRINUSE";
            else if (r == EINVAL) serr = "EINVAL";
            else if (r == ENOTSOCK) serr = "ENOTSOCK";
            else if (r == EADDRNOTAVAIL) serr = "EADDRNOTAVAIL";

            else if (r == EFAULT) serr = "EFAULT";
            else if (r == ELOOP) serr = "ELOOP";
            else if (r == ENAMETOOLONG) serr = "ENAMETOOLONG";
            else if (r == ENOENT) serr = "ENOENT";
            else if (r == ENOMEM) serr = "ENOMEM";
            else if (r == ENOTDIR) serr = "ENOTDIR";
            else if (r == EROFS) serr = "ENOTEROFSDIR";
#endif
			throw std::runtime_error("Could not bind socket " + serr);
		}
	}

	void crypto_server::listenServer() {
		if (listen(this->m_socketFd, this->_cfg._number_connection) == -1) {
			throw std::runtime_error("Could not open socket for listening");
		}
	}

	void crypto_server::handle_new_client(socket_node* new_client)
	{
		// send current list
		handle_info_client(new_client->getSocketFd(), false);
	}
    void crypto_server::handle_remove_client()
    {
    }
    void crypto_server::handle_info_client(const int& t_socket, bool send_to_current_user_only)
    {
        // new user_index, hostname, username
		std::string v;
		{
			std::lock_guard lck(vclient_mutex);
			std::string s;
			for(size_t i=0; i<v_client.size();i++)
			{
                if (v_client[i]->user_index > 0 && v_client[i]->hostname.size() > 0 && v_client[i]->username.size() > 0)
                {
                    s=std::to_string(v_client[i]->user_index) + ";" + v_client[i]->hostname + ";" + v_client[i]->username + ";";
                    v+=s;
                }
			}
		}

		// MSG_CMD_INFO_USERLIST
		if (v.size() > 0)
		{
			if (send_to_current_user_only)
				sendMessageOneBySocket(v, t_socket, NETW_MSG::MSG_CMD_INFO_USERLIST,0,0,0);
			else
				sendMessageClients(v, NETW_MSG::MSG_CMD_INFO_USERLIST,0,0,0);
        }
    }

	void crypto_server::handle_accept()
	{
		showMessage("crypto_server is running...");
		showMessage(std::string(inet_ntoa(this->m_socketInfo.sin_addr)) + ":" + std::to_string(ntohs(this->m_socketInfo.sin_port)));

		while (1)
		{
			struct sockaddr_in temp_addr;
			socklen_t temp_len = sizeof (temp_addr);

			// ACCEPT
			int temp_socket = accept(this->m_socketFd, reinterpret_cast<sockaddr*> (&temp_addr), &temp_len);

			// check connection limit
			if (this->m_nodeSize + 1 > this->_cfg._number_connection)
			{
				NETW_MSG::MSG  m;
				m.make_msg(NETW_MSG::MSG_TEXT, "Server is full.", getDEFAULT_KEY());
				std::stringstream serr;
				send_composite(temp_socket, m, getDEFAULT_KEY(), serr);
				if (DEBUG_INFO)
					std::cout << serr.str();
#ifdef _WIN32
				closesocket(temp_socket);
#else
				close(temp_socket);
#endif
				continue;
			}
			this->m_nodeSize += 1;

			// NEW CLIENT
			client_node* new_client = new client_node();
			new_client->setSocketInfo(temp_addr);
			new_client->setSocketFd(temp_socket);
			new_client->setState(STATE::OPEN);

			std::string client_ip(inet_ntoa(temp_addr.sin_addr));
			std::string client_port(std::to_string(ntohs(temp_addr.sin_port)));

            // * getpeername
            struct sockaddr_in peeraddr;
            socklen_t peeraddrlen;

            int retval = getpeername(temp_socket, (struct sockaddr *) &peeraddr, &peeraddrlen);
            if (retval == -1)
            {
            }
            else
            {
                char *peeraddrpresn = inet_ntoa(peeraddr.sin_addr);

                printf("Peer information:\n");
                printf("Peer Address Family: %d\n", peeraddr.sin_family);
                printf("Peer Port: %d\n", ntohs(peeraddr.sin_port));
                printf("Peer IP Address: %s\n\n", peeraddrpresn);
            }

			//------------------------------------
			// One RECV thread per client
			//------------------------------------
			this->v_thread.push_back(std::thread([ = , this]
			{
				bool msg_ok = true;
				int len;
				size_t byte_recv = 0;
				uint32_t expected_len = 0;
				size_t msg_counter = 0;
				char message_buffer[NETW_MSG::MESSAGE_SIZE + 1];
				char message_previous_buffer[NETW_MSG::MESSAGE_SIZE + 1];

				// RECV ()
				while(msg_ok)
				{
					if (new_client->getState() == STATE::CLOSED)
					{
						msg_ok = false;
						std::cout << "WARNING recv() - exiting a thread, client socket is STATE::CLOSED" << std::endl;
						break;
					}

					if (byte_recv > 0)
					{
						memcpy(message_buffer, message_previous_buffer, byte_recv);
						std::cout << "recv() bytes from previous " << byte_recv << std::endl;
					}

					while (byte_recv < NETW_MSG::MESSAGE_HEADER)
					{
                        if (DEBUG_INFO)
                        {
                            std::cout << std::endl;
                            std::cout << "while (byte_recv < NETW_MSG::MESSAGE_HEADER)" << std::endl;
						}

                        if (new_client->getState() == STATE::CLOSED)
                        {
                            msg_ok = false;
                            std::cout << "WARNING recv() - exiting a recv thread, client socket is STATE::CLOSED" << std::endl;
                            break;
                        }

						len = recv(new_client->getSocketFd(), message_buffer + byte_recv, NETW_MSG::MESSAGE_HEADER - byte_recv, 0);
						if (len > 0)
						{
							byte_recv += len;
							if (DEBUG_INFO)
                                std::cout << "recv() bytes total " << byte_recv << std::endl;
						}
						else
						{
							// closed or error
							if (len == 0)
								std::cout << "WARNING recv() - socket closed"  << std::endl;
							else
							{
#ifdef _WIN32
								if (len == SOCKET_ERROR)
								{
									std::cout << "ERROR - recv() failed with error: " << WSAGetLastError();
								}
#else
								if (len == -1)
								{
									std::cout << "ERROR - recv() failed with error: " << errno << " " << strerror(errno) << "\n";
								}
#endif
							}
							msg_ok = false;
							break;
						}
					}

					//------------------------------------------------------
					// Validate 1 th message send by a client - abort if wrong
					//------------------------------------------------------
					if (msg_counter == 0)
					{
                        bool ok = true;

						uint8_t original_flag	= message_buffer[NETW_MSG::MESSAGE_FLAG_START];
						uint32_t from_user		= NETW_MSG::MSG::byteToUInt4((char*)message_buffer+NETW_MSG::MESSAGE_FROM_START);
                        uint32_t to_user		= NETW_MSG::MSG::byteToUInt4((char*)message_buffer+NETW_MSG::MESSAGE_TO_START);

                        if (memcmp(message_buffer + NETW_MSG::MESSAGE_SIGNATURE_START, NETW_MSG::MESSAGE_SIGNATURE, 20) != 0)
                        {
                            ok = false;
                        }
//                        if (ok)
//                        {
//                            if (message_buffer[0] != NETW_MSG::MSG_FIRST)
//                                ok = false;
//                        }
//                        if (ok && from_user != 0)
//                        {
//                            ok = false;
//                        }
//                        if (ok && to_user != 0)
//                        {
//                            ok = false;
//                        }
//                        //...

                        if (ok == false)
                        {
                            msg_ok = false;
                            std::cout << "WARNING recv() - exiting a thread, invalid 1 th message" << std::endl;
                            break;
                        }
					}

					expected_len = NETW_MSG::MSG::byteToUInt4(message_buffer + 1);
					if (msg_counter == 0)
					{
                        if (expected_len > NETW_MSG::MESSAGE_SIZE)
                        {
                            msg_ok = false;
                            std::cout << "WARNING recv() - exiting a thread, invalid 1 th message" << std::endl;
                            break;
                        }
                    }

					cryptoAL::cryptodata recv_buffer; // new instance ...//recv_buffer.erase(use default init size); // TODO
					if (byte_recv > 0)
					{
						recv_buffer.buffer.write(message_buffer, byte_recv);
					}

					size_t len_recv_buffer_call = 0;
					while (byte_recv < expected_len)
					{
                        if (DEBUG_INFO)
                            std::cout << "while (byte_recv < expected_len)" << std::endl;

                        if (new_client->getState() == STATE::CLOSED)
                        {
                            msg_ok = false;
                            std::cout << "WARNING recv() - exiting a recv client thread, socket is STATE::CLOSED" << std::endl;
                            break;
                        }

						len_recv_buffer_call = expected_len - byte_recv;
						if (len_recv_buffer_call > NETW_MSG::MESSAGE_SIZE) len_recv_buffer_call = NETW_MSG::MESSAGE_SIZE;

						len = recv(new_client->getSocketFd(), message_buffer, (int)len_recv_buffer_call, 0);
						if (len > 0)
						{
							byte_recv += len;
							recv_buffer.buffer.write(message_buffer, len);
							if (DEBUG_INFO)
                                std::cout << "recv() bytes total " << byte_recv << std::endl;
						}
						else
						{
                            if (DEBUG_INFO)
                            {
                                if (len == 0)
                                    std::cout << "WARNING recv() - socket closed" << std::endl;
								else
								{
#ifdef _WIN32
									if (len == SOCKET_ERROR)
									{
										std::cout << "ERROR - recv() failed with error: " << WSAGetLastError();
									}
#else
									if (len == -1)
									{
										std::cout << "ERROR - recv() failed with error: " << errno << " " << strerror(errno) << "\n";
									}
#endif
								}
                            }
							msg_ok = false;
							break;
						}
					}

					if (msg_ok)
					{
						// remaining data for next msg
						if (byte_recv >= expected_len)
						{
							byte_recv = byte_recv - expected_len;
							if (byte_recv > 0)
							{
								if (byte_recv <= NETW_MSG::MESSAGE_SIZE)
									memcpy(message_previous_buffer, message_buffer, byte_recv);
								else
								{
									// TODO...
									std::cout << "WARNING recv() - excess data recv" << byte_recv << std::endl;
								}
							}
						}

						uint8_t original_flag	= recv_buffer.buffer.getdata()[NETW_MSG::MESSAGE_FLAG_START];
						uint32_t from_user		= NETW_MSG::MSG::byteToUInt4((char*)recv_buffer.buffer.getdata()+NETW_MSG::MESSAGE_FROM_START);
                        uint32_t to_user		= NETW_MSG::MSG::byteToUInt4((char*)recv_buffer.buffer.getdata()+NETW_MSG::MESSAGE_TO_START);

						std::cout	<< "recv msg (from socket:" << new_client->getSocketFd() << ")"
									<< " type:" << std::to_string((int)recv_buffer.buffer.getdata()[0])
									<< " crypto:" << std::to_string((int)original_flag)
									<< " from_user: " << from_user
									<< " to_user: " << to_user
									<< " len: " << expected_len
									<< std::endl;

						// Parse message
						NETW_MSG::MSG m;
						bool r;
						if (recv_buffer.buffer.getdata()[0] == NETW_MSG::MSG_CMD_RESP_KEY_HINT)
							r = m.parse((char*)recv_buffer.buffer.getdata(), expected_len, getDEFAULT_KEY());
						else if (!new_client->initial_key_validation_done)
							r = m.parse((char*)recv_buffer.buffer.getdata(), expected_len, getDEFAULT_KEY());
						else if (!new_client->random_key_validation_done)
							r = m.parse((char*)recv_buffer.buffer.getdata(), expected_len, new_client->initial_key64);
						else
							r = m.parse((char*)recv_buffer.buffer.getdata(), expected_len, new_client->random_key, new_client->previous_random_key, new_client->pending_random_key);

						if (r && msg_counter == 0)
                        {
                            std::string msg1 = m.get_data_as_string();

                            if (msg1 != "hello")
                            {
                                msg_ok = false;
                                std::cout << "WARNING recv() - exiting a thread, invalid 1 th message" << std::endl;
                                break;
                            }
                        }

						if (r == true)
						{
                            msg_counter++;

							if (m.type_msg == NETW_MSG::MSG_CMD_RESP_KEY_HINT)
							{
								handle_msg_MSG_CMD_RESP_KEY_HINT(m, new_client);
							}
							else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_ACCEPT_RND_KEY)
							{
                                handle_msg_MSG_CMD_RESP_ACCEPT_RND_KEY(m, new_client);
							}
							else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_USERNAME)
							{
                                handle_msg_MSG_CMD_RESP_USERNAME(m, new_client);
							}
							else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_HOSTNAME)
							{
								if (DEBUG_INFO)
									std::cout << "recv MSG_CMD_RESP_HOSTNAME" << std::endl;

								std::string host = m.get_data_as_string();
								if (host.size() != 0)
								{
									new_client->hostname = host;
									std::cout << "INFO client[" << new_client->getSocketFd() << "] hostname:" << new_client->hostname << std::endl;
								}
								handle_info_client(new_client->getSocketFd());
							}
							else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_MACHINEID)
							{
                                handle_msg_MSG_CMD_RESP_MACHINEID(m, new_client);
							}

							// RELAY
							else if (m.type_msg == NETW_MSG::MSG_FILE_FRAGMENT)
							{
								if (DEBUG_INFO) std::cout << "recv MSG_FILE_FRAGMENT : " << std::endl;
								if (DEBUG_INFO) std::cout << std::string((char*)m.buffer + NETW_MSG::MESSAGE_HEADER, 40) << std::endl;

								bool send_to_one = false;

								if (to_user != 0)
								{
									send_to_one = true;
								}

                                if (send_to_one == false)
                                {
                                    sendMessageAll(m, new_client->getSocketFd(),original_flag, from_user, to_user);
                                }
                                else
                                {
                                    this->sendMessageOne(m, m.type_msg, original_flag, from_user, to_user);
                                }
							}
							// RELAY
							else if (m.type_msg == NETW_MSG::MSG_FILE)
							{
								if (DEBUG_INFO) std::cout << "recv MSG_FILE : " << std::endl;
								std::string s = m.get_data_as_string(); // filename

								bool send_to_one = false;

								if (to_user != 0)
								{
									send_to_one = true;
								}

                                if (send_to_one == false)
                                {
                                    sendMessageAll(m, new_client->getSocketFd(),original_flag, from_user, to_user);
                                }
                                else
                                {
                                    this->sendMessageOne(m, m.type_msg, original_flag, from_user, to_user);
                                }
							}
							// RELAY
							else if (m.type_msg == NETW_MSG::MSG_TEXT)
							{
								bool send_to_one = false;

                                if (to_user != 0)
                                {
                                    send_to_one = true;
                                }

                                if (send_to_one == false)
                                {
                                    sendMessageAll(m, new_client->getSocketFd(),original_flag, from_user, to_user);
                                }
                                else
                                {
                                    this->sendMessageOne(m, m.type_msg, original_flag, from_user, to_user);
                                }

                                // new random encryption key per message
                                if (new_client->new_pending_random_key == true)
								{
                                    handle_new_pending_random_key(new_client);
								}
								else if (new_client->new_pending_random_key == false)
								{
									if (USE_BASE64_RND_KEY_GENERATOR == false)
										new_client->pending_random_key = cryptoAL::random::generate_base10_random_string(NETW_MSG::KEY_SIZE);
									else
										new_client->pending_random_key = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

									new_client->new_pending_random_key = true;
								}
                            }
                            else if (m.type_msg == NETW_MSG::MSG_VALIDATION)
							{
								if (!new_client->initial_key_validation_done)
								{
									this->request_client_initial_key(new_client);
								}
								else if (new_client->username.size() == 0)
								{
									if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_USERNAME " << new_client->getSocketFd() << std::endl;

									NETW_MSG::MSG m;
									std::string s = "Please, provide your username : ";
									m.make_msg(NETW_MSG::MSG_CMD_REQU_USERNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);
									std::stringstream serr;
									send_composite(new_client->getSocketFd(), m,
										new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
									if (DEBUG_INFO)
										std::cout << serr.str();
								}
								else if (!new_client->random_key_validation_done)
								{
									this->request_accept_rnd_key(new_client);
								}
							}
						}
					}
				}

				// connection closed. DELETING socket instance
				{
                    std::cerr << "INFO recv() - DELETING socket instance" << std::endl;
					std::lock_guard lck(vclient_mutex);
					this->v_client.erase(std::remove(this->v_client.begin(), this->v_client.end(), new_client));

					// TODO
					//this->m_nodeSize -= 1;
				}

				handle_remove_client();
				this->showMessage(client_ip + ":" + client_port + " disconnected.");
			}));

			this->showMessage(client_ip + ":" + client_port + " connected.");
			{
				std::lock_guard lck(vclient_mutex);
				this->v_client.push_back(new_client);
			}
			this->handle_new_client(new_client);
		}
	}

	void crypto_server::sendMessageClients( const std::string& t_message, uint8_t msg_type,
                                            uint8_t crypto_flag, uint8_t from_user, uint8_t to_user)
	{
		std::lock_guard lck(vclient_mutex);

		for (auto& client : v_client)
		{
			if (client->getState() == STATE::OPEN)
			{
				NETW_MSG::MSG  m;

				std::string key;
				if (!client->initial_key_validation_done) key = getDEFAULT_KEY();
				else if (!client->random_key_validation_done) key = client->initial_key64;
				else key = client->random_key;

				m.make_msg(msg_type, t_message, key);
				std::stringstream serr;
				send_composite(client->getSocketFd(), m, key, serr,crypto_flag, from_user, to_user);
				if (DEBUG_INFO)
					std::cout << serr.str();
			}
		}
	}

	void crypto_server::sendMessageClients(const std::string& t_message,
                                            uint8_t crypto_flag, uint8_t from_user, uint8_t to_user)
	{
		sendMessageClients(t_message, NETW_MSG::MSG_TEXT, crypto_flag, from_user, to_user);
	}

	// Relay message m
	void crypto_server::sendMessageAll(const std::string& t_message, const int& t_socket, uint8_t msg_type,
                                        uint8_t crypto_flag, uint8_t from_user, uint8_t to_user)
	{
		std::lock_guard lck(vclient_mutex);

		for (auto& client : v_client)
		{
			if (client->getSocketFd() != t_socket)
			{
				if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					NETW_MSG::MSG m;
					m.make_msg(msg_type, t_message, key);
					std::stringstream serr;
					send_composite(client->getSocketFd(), m, key, serr, crypto_flag, from_user, to_user);
					if (DEBUG_INFO)
						std::cout << serr.str();
				}
			}
		}
	}

	bool crypto_server::sendMessageOne(NETW_MSG::MSG& m, uint8_t msg_type,
                                        uint8_t crypto_flag, uint8_t in_from_user, uint8_t in_to_user)
	{
		bool r = false;
		std::lock_guard lck(vclient_mutex);

		for (auto& client : v_client)
		{
			if (client->user_index == in_to_user)
			{
				if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					std::stringstream serr;
					int ret = send_composite(client->getSocketFd(), m, key, serr, crypto_flag, in_from_user, in_to_user);
					if (ret >= 0)
						r = true;
                    if (DEBUG_INFO)
                        std::cout << serr.str();
				}
				break;
			}
		}
		return r;
	}

	bool crypto_server::sendMessageOneBySocket(const std::string& t_message, const int& t_socket, uint8_t msg_type,
                                                uint8_t crypto_flag, uint8_t in_from_user, uint8_t in_to_user)
	{
		bool r = false;
		std::lock_guard lck(vclient_mutex);

		for (auto& client : v_client)
		{
			if (client->getSocketFd() == t_socket)
			{
				if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					NETW_MSG::MSG m;
					m.make_msg(msg_type, t_message, key);

					m.buffer[NETW_MSG::MESSAGE_FLAG_START] = crypto_flag;
					NETW_MSG::MSG::uint4ToByte(in_from_user, (char*)m.buffer + NETW_MSG::MESSAGE_FROM_START);
					NETW_MSG::MSG::uint4ToByte(in_to_user,   (char*)m.buffer + NETW_MSG::MESSAGE_TO_START);

					std::stringstream serr;
					int ret = send_composite(client->getSocketFd(), m, key, serr, crypto_flag, in_from_user, in_to_user);
					if (ret >= 0)
						r = true;
                    if (DEBUG_INFO)
                        std::cout << serr.str();
				}
				break;
			}
		}
		return r;
	}

	void crypto_server::sendMessageAll(NETW_MSG::MSG& m, const int& t_socket,
                                        uint8_t crypto_flag, uint8_t in_from_user, uint8_t in_to_user)
	{
		std::lock_guard lck(vclient_mutex);

		for (auto& client : v_client)
		{
			if (client->getSocketFd() != t_socket)
			{
				if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					std::stringstream serr;
					send_composite(client->getSocketFd(), m, key, serr, crypto_flag, in_from_user, in_to_user);
					if (DEBUG_INFO)
                        std::cout << serr.str();
				}

			}
		}
	}

	// NETW_MSG::MSG_TEXT
	void crypto_server::sendMessageAll( const std::string& t_message, const int& t_socket,
                                        uint8_t crypto_flag, uint8_t from_user, uint8_t to_user)
	{
		sendMessageAll(t_message, t_socket, NETW_MSG::MSG_TEXT, crypto_flag, from_user, to_user);
	}

	void crypto_server::close_client(client_node* client,bool force)
	{
		if (client != nullptr)
		{
			if (client->getState() == STATE::OPEN)
			{
				// notify
				client->setState(STATE::CLOSED);

				// removed by RECV thread
				//	this->v_client.erase(std::remove(this->v_client.begin(), this->v_client.end(), new_client));
			}
		}
	}

    void crypto_server::request_all_client_shutdown()
	{
        for (auto& client : v_client)
		{
            std::string key;
            if (!client->initial_key_validation_done) key = getDEFAULT_KEY();
            else if (!client->random_key_validation_done) key = client->initial_key64;
            else key = client->random_key;

			NETW_MSG::MSG m;
			m.make_msg(NETW_MSG::MSG_CMD_REQU_SHUTDOWN, "shutdown", key);
			std::stringstream serr;
			send_composite(client->getSocketFd(), m, key, serr);
			if (DEBUG_INFO)
                std::cout << serr.str();
		}
	}

	void crypto_server::request_client_initial_key(client_node* client)
	{
		if (!client->initial_key_validation_done)
		{
			if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_KEY_HINT " << client->getSocketFd() << std::endl;

			NETW_MSG::MSG m;
			std::string s = initial_key_hint;
			m.make_msg(NETW_MSG::MSG_CMD_REQU_KEY_HINT, s, getDEFAULT_KEY());
			std::stringstream serr;
			send_composite(client->getSocketFd(), m, getDEFAULT_KEY(),serr);
			if (DEBUG_INFO)
                std::cout << serr.str();
		}
	}

	void crypto_server::request_accept_rnd_key(client_node* client)
	{
		if (!client->random_key_validation_done)
		{
			if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << client->getSocketFd() << std::endl;
			if (DEBUG_INFO)
				std::cout << "First Random key send ["
				+ file_util::get_summary_hex((char*)first_pending_random_key.data(), first_pending_random_key.size())
				+ "]" << std::endl;

			SHA256 sha;
			sha.update((uint8_t*)first_pending_random_key.data(), first_pending_random_key.size());
			uint8_t* digestkey = sha.digest();
			std::string str_digest = sha.toString(digestkey);
			delete[]digestkey;

			if (DEBUG_INFO)
				std::cout << "First Random key send digest ["
					+ str_digest
					+ "]" << std::endl;

			NETW_MSG::MSG m;
			client->pending_random_key = first_pending_random_key;

			m.make_msg(NETW_MSG::MSG_CMD_REQU_ACCEPT_RND_KEY, client->pending_random_key,
				client->random_key_validation_done ? client->random_key : client->initial_key64);
			std::stringstream serr;
			send_composite(client->getSocketFd(), m, client->random_key_validation_done ? client->random_key : client->initial_key64, serr);
			if (DEBUG_INFO)
                std::cout << serr.str();
		}
	}

	void crypto_server::close_all_clients()
	{
        request_all_client_shutdown();

        std::cout << "delete all clients" << std::endl;
		std::lock_guard lck(vclient_mutex);
		for (auto &client : v_client) {
			delete client;
		}
	}

	void crypto_server::join_all_recv_threads()
	{
        std::cout << "join_all_recv_threads" << std::endl;
		for (auto &thread : v_thread) {
			if (thread.joinable()) {
				thread.join();
			}
		}
		std::cout << "join_all_recv_threads done" << std::endl;
	}

	void crypto_server::closeServer()
	{
        std::cout << "closeServer" << std::endl;
		sendMessageClients("Server closed.",0,0,0);

		this->close_all_clients();
		this->closeSocket();
		this->join_all_recv_threads();

		this->v_client.clear();
		this->v_thread.clear();
	}

	crypto_server::~crypto_server()
	{
        std::cout << "~crypto_server" << std::endl;
		save_map_machineid_to_user_index();
		this->closeServer();
	}



	void crypto_server::handle_msg_MSG_CMD_RESP_KEY_HINT(NETW_MSG::MSG& m, client_node* new_client)
	{
		if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_KEY_HINT" << std::endl;
		if (DEBUG_INFO) std::cout.flush();

		std::string s = m.get_data_as_string();
		if (s == initial_key)
		{
			if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_KEY_VALID " << new_client->getSocketFd() << std::endl;

			NETW_MSG::MSG m;
			m.make_msg(NETW_MSG::MSG_CMD_INFO_KEY_VALID, "Initial key is valid", getDEFAULT_KEY());
			std::stringstream serr;
			send_composite(new_client->getSocketFd(), m, getDEFAULT_KEY(),serr);
			std::cout << serr.str();

			new_client->initial_key = initial_key;
			new_client->initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
			new_client->initial_key_validation_done = true;

			if (new_client->username.size() == 0)
			{
				if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_USERNAME " << new_client->getSocketFd() << std::endl;
				NETW_MSG::MSG m;
				std::string s = "Please, provide your username : ";
				m.make_msg(NETW_MSG::MSG_CMD_REQU_USERNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);
				std::stringstream serr;
				send_composite(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
				if (DEBUG_INFO)
                    std::cout << serr.str();
			}

			if (new_client->hostname.size() == 0)
			{
				if (DEBUG_INFO)
					std::cout << "send MSG_CMD_REQU_HOSTNAME " << new_client->getSocketFd() << std::endl;
				NETW_MSG::MSG m;
				std::string s = "Please, provide your hostname : ";
				m.make_msg(NETW_MSG::MSG_CMD_REQU_HOSTNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);
				std::stringstream serr;
				send_composite(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64,serr);
				if (DEBUG_INFO)
                    std::cout << serr.str();
			}

			if (new_client->machine_id.size() == 0)
			{
				if (DEBUG_INFO)
					std::cout << "send MSG_CMD_REQU_MACHINEID " << new_client->getSocketFd() << std::endl;
				NETW_MSG::MSG m;
				std::string s = "Please, provide your id : ";
				m.make_msg(NETW_MSG::MSG_CMD_REQU_MACHINEID, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);
				std::stringstream serr;
				send_composite(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64,serr);
				if (DEBUG_INFO)
                    std::cout << serr.str();
			}
		}
		else
		{
			std::cerr << "WARNING invalid initial_key recv " << new_client->getSocketFd() << " " << s << std::endl;
			if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_KEY_INVALID " << new_client->getSocketFd() << std::endl;

			NETW_MSG::MSG m;
			m.make_msg(NETW_MSG::MSG_CMD_INFO_KEY_INVALID, "Initial key is INVALID", getDEFAULT_KEY());
			std::stringstream serr;
			send_composite(new_client->getSocketFd(), m, getDEFAULT_KEY(), serr);
			if (DEBUG_INFO)	std::cout << serr.str();

			if (!new_client->initial_key_validation_done)
			{
				this->request_client_initial_key(new_client);
			}

			new_client->count_initial_key_validation++;
			if (new_client->count_initial_key_validation >= 3)
			{
				// Kill client......
				std::cerr << "WARNING client exceed number of challenge attempt limit - closing socket : " << new_client->getSocketFd() << " " << std::endl;
				close_client(new_client);
			}
		}
	}

	bool crypto_server::read_map_machineid_to_user_index()
	{
		try
		{
			std::string filename = this->_cfg._machineid_filename;
			std::ifstream infile;
			infile.open(filename, std::ios_base::in);
			infile >> bits(next_user_index);
			infile >> bits(map_machineid_to_user_index);
			infile.close();
		}
		catch (...)
		{
			std::cerr << "WARNING map_machineid can not be read " << this->_cfg._machineid_filename;
			return false;
		}
		for (auto& e : map_machineid_to_user_index)
		{
			for (auto& v : e.second)
			{
				v.status = 0; // no active
			}
		}

		std::cout << "next_user_index: " << next_user_index << std::endl;

		save_map_machineid_to_user_index();
		return true;
	}

	bool crypto_server::save_map_machineid_to_user_index()
	{
		try
		{
			std::string filename = this->_cfg._machineid_filename;
			std::ofstream out;
			out.open(filename, std::ios_base::out);
			out << bits(next_user_index);
			out << bits(map_machineid_to_user_index);
			out.close();
		}
		catch (...)
		{
			return false;
		}
		return true;
	}

	void crypto_server::handle_msg_MSG_CMD_RESP_ACCEPT_RND_KEY(NETW_MSG::MSG& m, client_node* new_client)
	{
        {
            if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
            if (DEBUG_INFO) std::cout.flush();

            std::string s = m.get_data_as_string(); // rnd key digest

            SHA256 sha;
            sha.update((uint8_t*)new_client->pending_random_key.data(), new_client->pending_random_key.size());
            uint8_t* digestkey = sha.digest();
            std::string str_digest = sha.toString(digestkey);
            delete[]digestkey;

            if (s == str_digest)
            {
                if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_RND_KEY_VALID " << new_client->getSocketFd() << std::endl;

                NETW_MSG::MSG m;
                m.make_msg(NETW_MSG::MSG_CMD_INFO_RND_KEY_VALID, "Random key is valid",
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

                std::stringstream serr;
                send_composite(new_client->getSocketFd(), m,
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);

                if (DEBUG_INFO)
                    std::cout << serr.str();

                new_client->previous_random_key = new_client->random_key;
                new_client->random_key = new_client->pending_random_key;

                new_client->random_key_validation_done = true;
                new_client->new_pending_random_key = false;
            }
            else
            {
                std::cout << "recv MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
                std::cout << "ERROR received invalid random_key digest " << new_client->getSocketFd() << " " << s << std::endl;
            }
        }
    }

    void crypto_server::handle_msg_MSG_CMD_RESP_USERNAME(NETW_MSG::MSG& m, client_node* new_client)
    {
        if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_USERNAME" << std::endl;

        std::string user = m.get_data_as_string();
        if (user.size() == 0) user = "user";
        new_client->username = user + "_" + std::to_string(new_client->getSocketFd()) ;
        std::cout << "INFO client[" << new_client->getSocketFd() << "] username:" << new_client->username << std::endl;

        {
            if (DEBUG_INFO) std::cout << "send MSG_CMD_ACCEPT_USERNAME " << new_client->getSocketFd() << std::endl;

            NETW_MSG::MSG msg;
            msg.make_msg(NETW_MSG::MSG_CMD_ACCEPT_USERNAME, new_client->username,
                new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

            std::stringstream serr;
            send_composite(new_client->getSocketFd(), msg,
                new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
            if (DEBUG_INFO)
                std::cout << serr.str();
        }
        handle_info_client(new_client->getSocketFd());
    }

    void crypto_server::handle_msg_MSG_CMD_RESP_MACHINEID(NETW_MSG::MSG& m, client_node* new_client)
    {
        if (DEBUG_INFO)	std::cout << "recv MSG_CMD_RESP_MACHINEID" << std::endl;

        std::string id = m.get_data_as_string();
        if (id.size() != 0)
        {
            new_client->machine_id = id;
            std::cout << "INFO client[" << new_client->getSocketFd() << "] id:" << new_client->machine_id << std::endl;

            if (map_machineid_to_user_index.contains(id) == false)
            {
                new_client->user_index = next_user_index;
                next_user_index++;
                map_machineid_to_user_index[id].push_back({new_client->user_index, 1});
                save_map_machineid_to_user_index();

                std::cout << "New machineid added, user= " << new_client->user_index << std::endl;

                if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_USERINDEX " << new_client->getSocketFd() << std::endl;

                NETW_MSG::MSG m;
                std::string s = std::to_string(new_client->user_index);
                m.make_msg(NETW_MSG::MSG_CMD_INFO_USERINDEX, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);
                std::stringstream serr;
                send_composite(new_client->getSocketFd(), m,
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
                if (DEBUG_INFO)
                    std::cout << serr.str();

                // new_client->user_index changed =>MSG_CMD_INFO_USERLIST
                handle_info_client(new_client->getSocketFd());
            }
            else if (new_client->user_index == 0)
            {
                // handle multiple instance on same machineid....
                bool user_index_exist = false;

                for (auto& v : map_machineid_to_user_index[id])
                {
                    if (v.status == 0)
                    {
                        user_index_exist = true;
                        new_client->user_index = v.index;
                        v.status = 1;
                        break;
                    }
                }

                if (user_index_exist)
                {
                    //save_map_machineid_to_user_index();
                }
                else
                {
                    new_client->user_index = next_user_index;
                    map_machineid_to_user_index[id].push_back({new_client->user_index, 1});
                    next_user_index++;
                    save_map_machineid_to_user_index();
                }

                if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_USERINDEX " << new_client->getSocketFd() << std::endl;

                NETW_MSG::MSG m;
                std::string s = std::to_string(new_client->user_index);
                m.make_msg(NETW_MSG::MSG_CMD_INFO_USERINDEX, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);
                std::stringstream serr;
                send_composite(new_client->getSocketFd(), m,
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
                if (DEBUG_INFO)
                    std::cout << serr.str();

                // new_client->user_index changed =>MSG_CMD_INFO_USERLIST
                handle_info_client(new_client->getSocketFd());

            }
        }
        handle_info_client(new_client->getSocketFd());
    }

    void crypto_server::handle_new_pending_random_key(client_node* new_client)
    {
        std::string work = new_client->pending_random_key;

        if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << new_client->getSocketFd() << std::endl;
        if (DEBUG_INFO)
            std::cout << "Random key send ["
            + file_util::get_summary_hex((char*)work.data(), work.size())
            + "]" << std::endl;

        SHA256 sha;
        sha.update((uint8_t*)work.data(), work.size());
        uint8_t* digestkey = sha.digest();
        std::string str_digest = sha.toString(digestkey);
        delete[]digestkey;

        if (DEBUG_INFO)
        {
            std::cout << "Random key send digest ["
                + str_digest
                + "]" << std::endl;

            CRC32 chk;
            chk.update((char*)work.data(), work.size());
            std::cout << "Random key send CRC32 ["
                << chk.get_hash()
                << "]" << std::endl;

            std::cout << "Random key send ["
                << work
                << "]" << std::endl;
        }

        NETW_MSG::MSG m;
        m.make_msg(NETW_MSG::MSG_CMD_REQU_ACCEPT_RND_KEY, new_client->pending_random_key,
            new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

        std::stringstream serr;
        send_composite(new_client->getSocketFd(), m,
            new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64,serr);
        if (DEBUG_INFO)
            std::cout << serr.str();
    }

}
