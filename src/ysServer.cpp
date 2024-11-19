/*
 * Author: Alain Lanthier
 */

#include "../include/challenge.hpp"
#include "../include/crc32a.hpp"
#include "../include/SHA256.h"
#include "../include/ysServer.h"
#include <iostream>
#include <string>

#ifdef _WIN32
#pragma warning(disable : 4996)
#endif

namespace ysSocket {

	void ysServer::setDefault() {
		this->m_socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	void ysServer::showMessage(const std::string& t_message) {
		if (this->m_onMessage != nullptr) {
			std::lock_guard<std::mutex> locker(this->m_mu);
			this->m_onMessage(t_message);
		}
	}

	ysServer::ysServer(cryptochat::cfg::cfg_srv cfg) :
		ysNodeV4(cfg._port),
		_cfg(cfg)
	{
		setDefault();
	}


	void ysServer::setOnMessage(const std::function<void(const std::string&)>& t_function) {
		m_onMessage = t_function;
	}

	void ysServer::runServer()
	{
		this->createServer();
		this->bindServer();
		this->listenServer();


		// TEST
		//{
		//	std::map<std::string, std::string> map_out;
		//	std::string out_error;
		//	bool r = NETW_MSG::challenge_read_from_file("C:\\cpp\\CryptoChat\\challenge.txt", map_out, out_error);
		//}

		// 
		// TEST MSG_FILE_FRAGMENT_HEADER
		//{
		//	NETW_MSG::MSG_FILE_FRAGMENT_HEADER h;
		//	h.filename = "C:\\tmp\\f.txt";
		//	h.total_size = std::to_string(52);
		//	h.from = std::to_string(0);
		//	h.to = std::to_string(52-1);

		//	NETW_MSG::MSG_FILE_FRAGMENT_HEADER hh;
		//	bool r = hh.parse_header(h.make_header());

		//	std::vector<NETW_MSG::MSG_FILE_FRAGMENT_HEADER> vout;
		//	r = NETW_MSG::MSG_FILE_FRAGMENT_HEADER::make_fragments("C:\\tmp\\smartgit-win-24_1_0.zip", vout);
		//}


		// TEST ENCRYPTION
		char buff[4];
		NETW_MSG::MSG::uint4ToByte(3453, buff);
		{
			uint32_t i = NETW_MSG::MSG::byteToUInt4(buff);
			if (i != 3453)
				throw std::runtime_error("Default key encryption not working");
		}

		const int N_SIZE_TEST = 10;
		{
			std::string key("key012345679");
			if (this->check_default_encrypt(key) == false)
			{
				throw std::runtime_error("Default encryption not working");
			}

			key = getDEFAULT_KEY();
			if (this->check_default_encrypt(key) == false)
			{
				throw std::runtime_error("Default key encryption not working");
			}

			// TEST cryptoAL_vigenere
			for(int i=0;i<N_SIZE_TEST;i++)
			{
				std::string bkey = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

				std::string bdat = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE / 2);
				std::string benc = cryptoAL_vigenere::encrypt_vigenere(bdat, bkey);
				std::string bdec = cryptoAL_vigenere::decrypt_vigenere(benc, bkey);
				if (bdat != bdec)
				{
					throw std::runtime_error("Vigenere key encryption not working on Base64");
				}
			}

			// TEST IDEA
//			{
//				idea id;
//
//				uint16_t data[4] = { 54,36,454,345 };
//				uint16_t key[8] = { 345,3453,5,3453,5,3556,46,4567 };
//				id.IDEA(data, key, true);
//				id.IDEA(data, key, false);
//			}
			for(int i=0;i<N_SIZE_TEST;i++)
			{
				std::string bkey = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE/8);
				std::string bdat = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE / 2);
				cryptoAL::cryptodata datain;
				cryptoAL::cryptodata dataenc;
				cryptoAL::cryptodata dataout;
				datain.buffer.write(bdat.data(), bdat.size());

				// "encode_idea data file must be multiple of 8 bytes idea: "
				// "encode_idea key must be multiple of 16 bytes: "

				bool r = NETW_MSG::MSG::encode_idea(datain, bkey.data(), bkey.size(), dataenc);
				if (r) r = NETW_MSG::MSG::decode_idea(dataenc, bkey.data(), bkey.size(), dataout);
				if (r) if (dataout.buffer.size() != bdat.size()) r = false;
				if (r) if (memcmp(dataout.buffer.getdata(),bdat.data(), bdat.size())!=0) r = false;
				if (!r)
				{
					throw std::runtime_error("IDEA key encryption not working on Base64");
				}
			}

			if (USE_BASE64_RND_KEY_GENERATOR == false)
				pending_random_key = cryptoAL::random::generate_base10_random_string(NETW_MSG::KEY_SIZE);
			else
				pending_random_key = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);
		}

		this->set_key_hint();
		this->handle_accept();
	}

	bool ysServer::check_default_encrypt(std::string& key)
	{
		NETW_MSG::MSG m, m2, m3;
		m.make_msg(NETW_MSG::MSG_TEXT, "Hello Test", key);

		m2.make_encrypt_msg(m, key);
		m3.make_decrypt_msg(m2, key);
		return m.is_same(m3);
	}

	//
	void ysServer::set_key_hint()
	{
		if (_cfg._map_challenges.size() > 0)
		{
			// pick one at random...
			auto iter = _cfg._map_challenges.begin();
			initial_key_hint = iter->first;
			initial_key = iter->second;

			std::cout << std::endl;
			std::cout << "INFO initial challenge set to : " << std::endl;
			_cfg.print_challenge(initial_key_hint, iter->second);
			std::cout << std::endl;
		}
		else
		{
			// ask user...
			//cryptoAL_vigenere::AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			initial_key_hint = "1th prime number\n1000th prime number";
			initial_key = "27919";
		}
	}

	void ysServer::createServer() {
		const int opt = 1;
		this->createSocket();
		if (setsockopt(this->m_socketFd, SOL_SOCKET, SO_REUSEADDR, (const char*) &opt, sizeof (opt))) {
			throw std::runtime_error("setsockopt");
		}
	}

	void ysServer::bindServer()
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

	void ysServer::listenServer() {
		if (listen(this->m_socketFd, this->_cfg._number_connection) == -1) {
			throw std::runtime_error("Could not open socket for listening");
		}
	}

	void ysServer::handle_accept()
	{
		showMessage("ysServer is running...");
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
				sendMessageBuffer(temp_socket, m, getDEFAULT_KEY());
#ifdef _WIN32
				closesocket(temp_socket);
#else
				close(temp_socket);
#endif
				continue;
			}
			this->m_nodeSize += 1;

			// NEW CLIENT
			ysNodeV4 * new_client = new ysNodeV4();
			new_client->setSocketInfo(temp_addr);
			new_client->setSocketFd(temp_socket);
			new_client->setState(STATE::OPEN);

			std::string client_ip(inet_ntoa(temp_addr.sin_addr));
			std::string client_port(std::to_string(ntohs(temp_addr.sin_port)));

			// One RECV thread per client
			this->v_thread.push_back(std::thread([ = , this]
			{
				bool msg_ok = true;
				int len;
				size_t byte_recv = 0;
				uint32_t expected_len = 0;
				char message_buffer[NETW_MSG::MESSAGE_SIZE + 1];
				char message_previous_buffer[NETW_MSG::MESSAGE_SIZE + 1];

				// RECV ()
				while(msg_ok)
				{
					if (new_client->getState() == STATE::CLOSED)
					{
						msg_ok = false;
						break;
					}

					if (byte_recv > 0)
					{
						memcpy(message_buffer, message_previous_buffer, byte_recv);
					}

					// recv on windows
					// If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received.
					// If the connection has been gracefully closed, the return value is zero.
					// Otherwise, a value of SOCKET_ERROR is returned, and a specific error code can be retrieved by calling WSAGetLastError.

					while (byte_recv < NETW_MSG::MESSAGE_HEADER)
					{
						len = recv(new_client->getSocketFd(), message_buffer + byte_recv, NETW_MSG::MESSAGE_SIZE - byte_recv, 0);
						if (len > 0)
						{
							byte_recv += len;
						}
						else
						{
							// closed or error
							std::cerr << "ERROR - socket error or closed" << std::endl;
							msg_ok = false;
							break;
						}
					}

					expected_len = NETW_MSG::MSG::byteToUInt4(message_buffer + 1);
					if (expected_len > NETW_MSG::MESSAGE_SIZE)
					{
						std::cerr << "ERROR - MSG has invalid expected len " << expected_len << " vs " << NETW_MSG::MESSAGE_SIZE << std::endl;
						msg_ok = false;
						break;
					}

					while (byte_recv < expected_len)
					{
						len = recv(new_client->getSocketFd(), message_buffer + byte_recv, NETW_MSG::MESSAGE_SIZE - byte_recv, 0);
						if (len > 0)
						{
							byte_recv += len;
						}
						else
						{
							// closed or error
							std::cerr << "ERROR - socket error or closed" << std::endl;
							msg_ok = false;
							break;
						}
					}

					if (msg_ok)
					{
						// remaining data for next msg
						byte_recv = byte_recv - expected_len;
						if (byte_recv > 0)
						{
							memcpy(message_previous_buffer, message_buffer + expected_len, byte_recv);
						}

						// Parse message
						NETW_MSG::MSG m;
						bool r;
						if (message_buffer[0] == NETW_MSG::MSG_CMD_RESP_KEY_HINT)
							r = m.parse(message_buffer, expected_len, getDEFAULT_KEY());
						else if (!new_client->initial_key_validation_done)
							r = m.parse(message_buffer, expected_len, getDEFAULT_KEY());
						else if (!new_client->random_key_validation_done)
							r = m.parse(message_buffer, expected_len, new_client->initial_key);
						else
							r = m.parse(message_buffer, expected_len, new_client->random_key, new_client->previous_random_key, new_client->pending_random_key);

						if (r == true)
						{
							if (m.type_msg == NETW_MSG::MSG_CMD_RESP_KEY_HINT)
							{
								if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_KEY_HINT" << std::endl;
								if (DEBUG_INFO) std::cout.flush();

								std::string s = m.get_data_as_string();
								if (s == initial_key)
								{
									if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_KEY_VALID " << new_client->getSocketFd() << std::endl;

									NETW_MSG::MSG m;
									m.make_msg(NETW_MSG::MSG_CMD_INFO_KEY_VALID, "Initial key is valid", getDEFAULT_KEY());
									sendMessageBuffer(new_client->getSocketFd(), m, getDEFAULT_KEY());

									new_client->initial_key = initial_key;
									new_client->initial_key_validation_done = true;

									if (new_client->username.size() == 0)
									{
										if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_USERNAME " << new_client->getSocketFd() << std::endl;
										NETW_MSG::MSG m;
										std::string s = "Please, provide your username : ";
										m.make_msg(NETW_MSG::MSG_CMD_REQU_USERNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);
										sendMessageBuffer(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);
									}

									if (new_client->hostname.size() == 0)
									{
										if (DEBUG_INFO)
											std::cout << "send MSG_CMD_REQU_HOSTNAME " << new_client->getSocketFd() << std::endl;
										NETW_MSG::MSG m;
										std::string s = "Please, provide your hostname : ";
										m.make_msg(NETW_MSG::MSG_CMD_REQU_HOSTNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);
										sendMessageBuffer(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);
									}
								}
								else
								{
									std::cerr << "WARNING invalid initial_key recv " << new_client->getSocketFd() << " " << s << std::endl;
									if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_KEY_INVALID " << new_client->getSocketFd() << std::endl;

									NETW_MSG::MSG m;
									m.make_msg(NETW_MSG::MSG_CMD_INFO_KEY_INVALID, "Initial key is INVALID", getDEFAULT_KEY());
									sendMessageBuffer(new_client->getSocketFd(), m, getDEFAULT_KEY());

									if (!new_client->initial_key_validation_done)
									{
										this->request_client_initial_key(new_client);
									}

									count_initial_key_validation++;
									if (count_initial_key_validation >= 3)
									{
										// Kill client......
									}
								}
							}
							else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_ACCEPT_RND_KEY)
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
										new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);

									sendMessageBuffer(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);

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
							else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_USERNAME)
							{
								if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_USERNAME" << std::endl;

								std::string user = m.get_data_as_string();
								if (user.size() == 0)
									user = "user";
                                new_client->username = user + "_" + std::to_string(new_client->getSocketFd()) ;
                                std::cout << "INFO client[" << new_client->getSocketFd() << "] username:" << new_client->username << std::endl;
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

									// if (new_client->username == NETW_MSG::DEFAULT_USERNAME)
									// {
										// new_client->username = "user_" + std::to_string(idx) + "_" + new_client->hostname;
										// std::cout << "INFO client[" << idx << "] username:" << new_client->username << std::endl;
									// }
								}
							}

							// RELAY
							else if (m.type_msg == NETW_MSG::MSG_FILE_FRAGMENT)
							{
								if (DEBUG_INFO) std::cout << "recv MSG_FILE_FRAGMENT : " << std::endl;
								if (DEBUG_INFO) std::cout << std::string((char*)m.buffer + NETW_MSG::MESSAGE_HEADER, 40) << std::endl;

								sendMessageAll(m, new_client->getSocketFd());
							}
							// RELAY
							else if (m.type_msg == NETW_MSG::MSG_FILE)
							{
								if (DEBUG_INFO) std::cout << "recv MSG_FILE : " << std::endl;
								std::string s = m.get_data_as_string(); // filename
								sendMessageAll(m, new_client->getSocketFd());
							}
							else if (m.type_msg == NETW_MSG::MSG_TEXT)
							{
								std::string username_display;
								if (new_client->username.size() > 0) username_display = " (" + new_client->username + ") ";
								std::string message(client_ip + ":" + client_port + username_display + "> " + m.get_data_as_string());

								this->sendMessageAll(message, new_client->getSocketFd());
								//this->sendMessageClients(message);

								if (!new_client->initial_key_validation_done)
								{
									this->request_client_initial_key(new_client);
								}
								else if (new_client->username.size() == 0)
								{
									if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_USERNAME " << new_client->getSocketFd() << std::endl;

									NETW_MSG::MSG m;
									std::string s = "Please, provide your username : ";
									m.make_msg(NETW_MSG::MSG_CMD_REQU_USERNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);
									sendMessageBuffer(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);
								}
								else if (!new_client->random_key_validation_done)
								{
									this->request_accept_rnd_key(new_client);
								}
								else if (new_client->new_pending_random_key)
								{
									std::string work = new_client->pending_random_key;

									if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << new_client->getSocketFd() << std::endl;
									if (DEBUG_INFO)
										std::cout << "Random key send ["
										+ get_summary_hex((char*)work.data(), work.size())
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
										new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);

									sendMessageBuffer(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key);
								}
								else
								{
									if (USE_BASE64_RND_KEY_GENERATOR == false)
										new_client->pending_random_key = cryptoAL::random::generate_base10_random_string(NETW_MSG::KEY_SIZE);
									else
										new_client->pending_random_key = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

									new_client->new_pending_random_key = true;
								}
							}
						}
					}

					std::memset(message_buffer, '\0', sizeof (message_buffer));
				}

				// connection closed. DELETING socket instance
				{
					std::lock_guard lck(vclient_mutex);
					this->v_client.erase(std::remove(this->v_client.begin(), this->v_client.end(), new_client));

					// TODO
					//this->m_nodeSize -= 1;
				}
				this->showMessage(client_ip + ":" + client_port + " disconnected.");
			}));

			this->showMessage(client_ip + ":" + client_port + " connected.");
			{
				std::lock_guard lck(vclient_mutex);
				this->v_client.push_back(new_client);
			}
		}
	}

	void ysServer::sendMessageClients(const std::string& t_message)
	{
		std::lock_guard lck(vclient_mutex);

		for (auto &client : v_client)
		{
			if (client->getState() == STATE::OPEN)
			{
				NETW_MSG::MSG  m;

				std::string key;
				if (!client->initial_key_validation_done)
					key = getDEFAULT_KEY();
				else if (!client->random_key_validation_done)
					key = client->initial_key;
				else
					key = client->random_key;

				m.make_msg(NETW_MSG::MSG_TEXT, t_message, key);
				sendMessageBuffer(client->getSocketFd(), m, key);
			}
		}
	}

	// Relay message m
	void ysServer::sendMessageAll(NETW_MSG::MSG& m, const int& t_socket)
	{
		std::lock_guard lck(vclient_mutex);

		for (auto& client : v_client)
		{
			if (client->getSocketFd() != t_socket)
			{
				if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done)
						key = getDEFAULT_KEY();
					else if (!client->random_key_validation_done)
						key = client->initial_key;
					else
						key = client->random_key;

					sendMessageBuffer(client->getSocketFd(), m, key);
				}

			}
		}
	}

	// NETW_MSG::MSG_TEXT
	void ysServer::sendMessageAll(const std::string& t_message, const int& t_socket)
	{
		std::lock_guard lck(vclient_mutex);

		for (auto &client : v_client) 
		{
			if (client->getSocketFd() != t_socket)
			{
				if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done)
						key = getDEFAULT_KEY();
					else if (!client->random_key_validation_done)
						key = client->initial_key;
					else
						key = client->random_key;

					NETW_MSG::MSG m;
					m.make_msg(NETW_MSG::MSG_TEXT, t_message, key);
					sendMessageBuffer(client->getSocketFd(), m, key);
				}
			}
		}
	}

	bool ysServer::close_client(ysNodeV4* client,bool force)
	{
		if (client->getState() == STATE::OPEN)
		{
			// notify
			client->setState(STATE::CLOSED);

			// removed by RECV thread 
			//	this->v_client.erase(std::remove(this->v_client.begin(), this->v_client.end(), new_client));
		}
	}

	void ysServer::request_client_initial_key(ysNodeV4* client)
	{
		if (!client->initial_key_validation_done)
		{
			if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_KEY_HINT " << client->getSocketFd() << std::endl;

			NETW_MSG::MSG m;
			std::string s = initial_key_hint;
			m.make_msg(NETW_MSG::MSG_CMD_REQU_KEY_HINT, s, getDEFAULT_KEY());
			sendMessageBuffer(client->getSocketFd(), m, getDEFAULT_KEY());
		}
	}

	void ysServer::request_accept_rnd_key(ysNodeV4* client)
	{
		if (!client->random_key_validation_done)
		{
			if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << client->getSocketFd() << std::endl;
			if (DEBUG_INFO)
				std::cout << "First Random key send ["
				+ get_summary_hex((char*)pending_random_key.data(), pending_random_key.size())
				+ "]" << std::endl;

			SHA256 sha;
			sha.update((uint8_t*)pending_random_key.data(), pending_random_key.size());
			uint8_t* digestkey = sha.digest();
			std::string str_digest = sha.toString(digestkey);
			delete[]digestkey;

			if (DEBUG_INFO)
				std::cout << "First Random key send digest ["
					+ str_digest
					+ "]" << std::endl;

			NETW_MSG::MSG m;
			client->pending_random_key = pending_random_key;

			m.make_msg(NETW_MSG::MSG_CMD_REQU_ACCEPT_RND_KEY, client->pending_random_key,
				client->random_key_validation_done ? client->random_key : client->initial_key);

			sendMessageBuffer(client->getSocketFd(), m, client->random_key_validation_done ? client->random_key : client->initial_key);
		}
	}

	void ysServer::closeClient() 
	{
		std::lock_guard lck(vclient_mutex);
		for (auto &client : v_client) {
			delete client;
		}
	}

	void ysServer::joinThread() {
		for (auto &thread : v_thread) {
			if (thread.joinable()) {
				thread.join();
			}
		}
	}

	void ysServer::closeServer() 
	{
		sendMessageClients("Server closed.");
		this->closeClient();
		this->closeSocket();
		this->joinThread();

		this->v_client.clear();
		this->v_thread.clear();
	}

	ysServer::~ysServer() {
		this->closeServer();
	}

}
