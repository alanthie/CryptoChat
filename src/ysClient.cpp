/*
 * Author: Alain Lanthier
 */

//g++ -c ysClient.cpp ysNodeV4.cpp ysServer.cpp ysChatClient.cpp ysChatServer.cpp -std=c++17
//g++ -o runclient ysClient.o ysNodeV4.o ysServer.o ysChatClient.o  -std=c++17 -pthread

#include <iostream>
#include <string>
#ifdef _WIN32
#include <conio.h>
#else
#endif

#include <stdlib.h>
#include <chrono>
#include "../include/ysClient.h"
#include "../include/crc32a.hpp"
#include "../include/Menu.h"
#include "../include/chat_cli.hpp" // std::atomic<int> cryptochat::cli::chat_cli::got_chat_cli_signal
#include "../include/main_global.hpp"

#include <ciso646>
#include <iostream>
#include <string>

extern int main_client_ui(ysSocket::ysClient* netw_client);

namespace ysSocket {

	std::string ysClient::get_input(const std::string& q)
	{
		std::cout << q << ": ";
		std::string message;
		//std::getline(std::cin, message);
		std::cin >> message;
		std::cout << std::endl;

		std::cin.ignore(0x7fffffffffffffff, '\n');
		std::cin.clear();

		return message;
	}

	bool ysClient::is_got_chat_cli_signal()
	{
		if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1) return true;
		return false;
	}

	void ysClient::setDefault() {
		inet_pton(AF_INET, this->m_serverName.c_str(), &this->m_socketInfo.sin_addr);
	}

	void ysClient::showMessage(const std::string& t_message) {
		if (this->m_onMessage != nullptr) {
			this->m_onMessage(t_message);
		}
	}

	void ysClient::_connectServer() {
		this->createSocket();

		int r = connect(this->m_socketFd, reinterpret_cast<sockaddr*> (&this->m_socketInfo), this->m_addressLen);
		if (r == -1)
		{
#ifdef _WIN32
			int r = WSAGetLastError();
			std::stringstream ss; ss << "WSAGetLastError() = " << r;
			main_global::log(ss.str());
#endif
			throw std::runtime_error("could not connect to server");
		}
	}

	// SEND FILE FRAGMENT THREAD
	void ysClient::send_pending_file_packet_thread()
	{
		this->m_send_thread = std::move(std::thread([=, this]
		{
			while (true)
			{
				if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
				{
					std::stringstream ss; ss << "Exiting thread send_pending_file_packet_thread " << std::endl;
					main_global::log(ss.str(), true);
					break;
				}

				std::string key;
				{
					std::lock_guard l(_key_mutex);

					if (!key_valid)	key = get_DEFAULT_KEY();
					else if (!rnd_valid) key = get_initial_key();
					else key = get_random_key();
				}

				int send_status;
				bool r = send_next_pending_file_packet(this->m_socketFd, key, send_status);
				if (!r)
				{
				}
				else{
                    ui_dirty = true;
				}
				// send TXT msg...

				// sleep ...
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}));
	}

	// RECV THREAD
	void ysClient::recv_thread()
	{
		this->m_recv_thread = std::move(std::thread([=, this]
		{
			bool msg_ok = true;
			int len;
			size_t byte_recv = 0;
			uint32_t expected_len = 0;
			char message_buffer[NETW_MSG::MESSAGE_SIZE + 1];
			char message_previous_buffer[NETW_MSG::MESSAGE_SIZE + 1];

			// RECV ()
			while (msg_ok)
			{
				if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
				{
					std::stringstream ss; ss << " Exiting thread recv_thread " << std::endl;
					main_global::log(ss.str(), true);
					msg_ok = false;
					break;
				}

				if (byte_recv > 0)
				{
					//std::cout << "RECV - byte_recv: " << byte_recv << std::endl;
					memcpy(message_buffer, message_previous_buffer, byte_recv);
				}

				// recv on windows
				// If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received.
				// If the connection has been gracefully closed, the return value is zero.
				// Otherwise, a value of SOCKET_ERROR is returned, and a specific error code can be retrieved by calling WSAGetLastError.

				while (byte_recv < NETW_MSG::MESSAGE_HEADER && msg_ok==true)
				{
					if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
					{
						std::stringstream ss; ss << " Exiting thread recv_thread " << std::endl;
						main_global::log(ss.str(), true);
						msg_ok = false;
						break;
					}

					len = recv(this->m_socketFd, message_buffer + byte_recv, NETW_MSG::MESSAGE_SIZE - byte_recv, 0);
					if (len > 0)
					{
						byte_recv += len;
						//std::cout << "RECV - byte_recv cumulative1: " << byte_recv << std::endl;
					}
					else
					{
						// closed or error
						std::stringstream ss; ss << "ERROR - socket error or closed" << std::endl;
						main_global::log(ss.str(),true);
						msg_ok = false;
						break;
					}
				}

				expected_len = NETW_MSG::MSG::byteToUInt4(message_buffer + 1);
				if (expected_len > NETW_MSG::MESSAGE_SIZE)
				{
					std::stringstream ss; ss << "ERROR - MSG has invalid expected len " << expected_len << " vs " << NETW_MSG::MESSAGE_SIZE << std::endl;
					main_global::log(ss.str());
					msg_ok = false;
					break;
				}

				while (byte_recv < expected_len && msg_ok==true)
				{
					if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
					{
						std::stringstream ss; ss << " Exiting thread recv_thread " << std::endl;
						main_global::log(ss.str(), true);
						msg_ok = false;
						break;
					}

					len = recv(this->m_socketFd, message_buffer + byte_recv, NETW_MSG::MESSAGE_SIZE - byte_recv, 0);
					if (len > 0)
					{
						byte_recv += len;
						//std::cout << "RECV - byte_recv cumulative2: " << byte_recv << std::endl;
					}
					else
					{
						// closed or error
						std::stringstream ss; ss << "ERROR - socket error or closed" << std::endl;
						main_global::log(ss.str());
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
						//std::cout << "RECV more - byte_recv remaining: " << byte_recv << std::endl;
					}
				}

				if (!msg_ok)
				{
					break;
				}

				message_buffer[expected_len] = '\0';

				// Parse message
				NETW_MSG::MSG m;
				bool r;

				{
					std::lock_guard l(_key_mutex);

					if (!key_valid)	r = m.parse(message_buffer, expected_len, getDEFAULT_KEY());
					else if (!rnd_valid) r = m.parse(message_buffer, expected_len, initial_key);
					else r = m.parse(message_buffer, expected_len, random_key, previous_random_key, pending_random_key);
				}

                if (r == true)
                {
					std::string str_message;
					if (m.type_msg != NETW_MSG::MSG_FILE_FRAGMENT)
						str_message = m.get_data_as_string();

                    if (m.type_msg == NETW_MSG::MSG_CMD_REQU_KEY_HINT)
                    {
                        challenge_attempt++;
                        std::vector<std::string> questions = NETW_MSG::split(str_message, ";");

						std::vector< std::string> a;
						for (size_t i = 0; i < questions.size(); i++) a.push_back({});

                        bool menu_abort = false;
                        while (true)
                        {
                            if (is_got_chat_cli_signal())
                            {
                                std::stringstream ss; ss << "Terminating menu" << std::endl;
                                main_global::log(ss.str(), true);
                                menu_abort = true;
                                break;
                            }

                            Menu qa;
                            qa.set_heading(std::string("Challenges (q TO QUIT MENU)")
                            + std::string(" [Attempt: ") + std::to_string(challenge_attempt) + "]");

                            qa.set_max_len(80);
                            for(size_t i = 0; i< questions.size(); i++)
                                qa.add_field( std::string("[" + std::to_string(i+1) + "] ") + questions[i] + " : " + a[i], nullptr);

                            // Blocking....to do
                            int c = qa.get_menu_choice();
                            if (c == 'q')
                            {
                                # ifdef _WIN32
                                    system("cls");
                                # else
                                    system("clear");
                                # endif
                                break;
                            }

                            int idx = c - '1';
                            if ((idx >= 0) && (idx < questions.size()))
                            {
                                // Blocking....to do
                                std::cout << std::endl;
                                a[idx] = get_input("Enter answer [" + std::to_string(idx+1) + "]");
                            }
                        }

                        if (!menu_abort)
                        {
                            std::string r;
                            for(size_t i = 0; i< questions.size(); i++)
                            {
                                r += a[i];
                                //if (i <  questions.size() - 1) r+=";";
                            }

                            {
                                //if (DEBUG_INFO)
                                {
                                    std::stringstream ss; ss << "recv MSG_CMD_REQU_KEY_HINT" << std::endl;
                                    main_global::log(ss.str());
                                }

                                {
                                    std::lock_guard l(_key_mutex);
                                    initial_key = r; // still key_valid = false;
                                }

                                //if (DEBUG_INFO)
                                {
                                    std::stringstream ss; ss << "send MSG_CMD_RESP_KEY_HINT" << std::endl;
                                    main_global::log(ss.str());
                                }
                                NETW_MSG::MSG m;
                                m.make_msg(NETW_MSG::MSG_CMD_RESP_KEY_HINT, r, getDEFAULT_KEY());
                                this->sendMessageBuffer(this->m_socketFd, m, getDEFAULT_KEY());
                            }
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_VALID)
                    {
                        {
							//if (DEBUG_INFO)
							{
								std::stringstream ss; ss << "recv MSG_CMD_INFO_KEY_VALID" << std::endl;
								main_global::log(ss.str());
							}

                            // CONFIRMED new key
                            key_valid = true;

                            showMessage(str_message);
                            add_to_history(true, NETW_MSG::MSG_CMD_INFO_KEY_VALID, str_message);
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_INVALID)
                    {
                        {
							//if (DEBUG_INFO)
							{
                                std::stringstream ss; ss << "recv MSG_CMD_INFO_KEY_INVALID" << std::endl;
                                main_global::log(ss.str());
							}

                            key_valid = false;

                            showMessage(str_message);
                            add_to_history(true, NETW_MSG::MSG_CMD_INFO_KEY_INVALID, str_message);
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_ACCEPT_RND_KEY)
                    {
                        pending_random_key = str_message;
                        std::string work = pending_random_key;

                        SHA256 sha;
                        sha.update((uint8_t*)work.data(), work.size());
                        uint8_t* digestkey = sha.digest();
                        std::string str_digest = sha.toString(digestkey);
                        delete[]digestkey;

                        std::stringstream ss;
                        ss << "recv MSG_CMD_REQU_ACCEPT_RND_KEY" << std::endl;

						if (DEBUG_INFO)
                        {
							ss << "Random key recv ["
                                + get_summary_hex((char*)work.data(), work.size())
                                + "]" << std::endl;

							 ss << "Random key digest recv ["
                                + str_digest
                                + "]" << std::endl;

                            CRC32 chk;
                            chk.update((char*)work.data(), work.size());
							ss << "Random key CRC32 recv ["
                            << chk.get_hash()
                            << "]" << std::endl;
                        }
                        main_global::log(ss.str());

						std::string key;
						{
							std::lock_guard l(_key_mutex);
							key = rnd_valid ? random_key : initial_key;
						}

						//if (DEBUG_INFO)
						{
                            std::stringstream ss; ss << "send MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
                            main_global::log(ss.str());
						}

						NETW_MSG::MSG m;
                        m.make_msg(NETW_MSG::MSG_CMD_RESP_ACCEPT_RND_KEY, str_digest, key);
                        this->sendMessageBuffer(this->m_socketFd, m, key);
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_RND_KEY_VALID)
                    {
                        {
							//if (DEBUG_INFO)
							{
                                std::stringstream ss; ss << "recv MSG_CMD_INFO_RND_KEY_VALID" << std::endl; main_global::log(ss.str());
							}

                            // CONFIRMED new rnd key
							{
								std::lock_guard l(_key_mutex);
								previous_random_key = random_key;
								random_key = pending_random_key;
								rnd_valid = true;
							}
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_USERNAME)
                    {
						//if (DEBUG_INFO)
						{
                            std::stringstream ss; ss << "recv MSG_CMD_REQU_USERNAME" << std::endl; main_global::log(ss.str());
						}

                        if (_cfg_cli._username.size() == 0)
                        {
                            showMessage(str_message);
                            std::string r = get_input("Enter username");
                            if (r.size() == 0) r = "user_xyz";
                            _cfg_cli._username = r;

                            _cfg_cli.save_cfg(_cfgfile);
                        }
                        user_valid = true;

						//if (DEBUG_INFO)
						{
                            std::stringstream ss; ss << "send MSG_CMD_RESP_USERNAME" << std::endl; main_global::log(ss.str());
						}
                        NETW_MSG::MSG m;

                        std::string key;
                        {
                            std::lock_guard l(_key_mutex);
                            key = rnd_valid ? random_key : initial_key;
                        }

                        m.make_msg(NETW_MSG::MSG_CMD_RESP_USERNAME, _cfg_cli._username, key);
                        this->sendMessageBuffer(this->m_socketFd, m, key);
                    }
					else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_HOSTNAME)
					{
						//if (DEBUG_INFO)
						{
                            std::stringstream ss; ss << "recv MSG_CMD_REQU_HOSTNAME" << std::endl; main_global::log(ss.str());
						}

						char host[80] = { 0 };
						if (gethostname(host, 80) == 0)
						{
							std::string h = std::string(host);

							//if (DEBUG_INFO)
							{
                                std::stringstream ss; ss << "send MSG_CMD_RESP_HOSTNAME " << h << std::endl; main_global::log(ss.str());
							}
							NETW_MSG::MSG m;

							std::string key;
							{
								std::lock_guard l(_key_mutex);
								key = rnd_valid ? random_key : initial_key;
							}

							m.make_msg(NETW_MSG::MSG_CMD_RESP_HOSTNAME, h, key);
							this->sendMessageBuffer(this->m_socketFd, m, key);
						}
						else
						{
							std::stringstream ss; ss << "WARNING gethostname failed" << std::endl;
							main_global::log(ss.str());
						}
					}
                    else if (m.type_msg == NETW_MSG::MSG_TEXT)
                    {
						//if (DEBUG_INFO)
						{
                            std::stringstream ss; ss << "recv MSG_TEXT : " << m.get_data_as_string() << std::endl;
                            main_global::log(ss.str());
						}

                        showMessage(str_message);
                        add_to_history(true, NETW_MSG::MSG_TEXT, str_message);
                        ui_dirty = true;
                    }

					else if (m.type_msg == NETW_MSG::MSG_FILE)
					{
						//if (DEBUG_INFO)
						{
                            std::stringstream ss; ss << "recv MSG_FILE : " << m.get_data_as_string() << std::endl; main_global::log(ss.str());
						}

						showMessage(str_message);
						std::string filename;
						std::string filename_key;
						int for_display = true;

						bool ok = false;
						if (str_message.size() > 6)
						{
							for (size_t p = 1; p < str_message.size(); p++)
							{
								if (str_message[p] == ',')
								{
									filename = str_message.substr(1, p - 1);
									for (size_t k = p+1; k < str_message.size(); k++)
									{
										if (str_message[k] == ',')
										{
											filename_key = str_message.substr(p + 1, k - 1 - p);
											if (str_message[k + 1] == '1') for_display = true;
											else for_display = false;

											ok = true;
											break;
										}
									}
									break;
								}
							}
						}

						if (ok)
						{
                            add_to_history(true, NETW_MSG::MSG_FILE, str_message, filename, filename_key, for_display);
                            ui_dirty = true;
						}
					}

					else if (m.type_msg == NETW_MSG::MSG_FILE_FRAGMENT)
					{
						//if (DEBUG_INFO)
						{
                            std::stringstream ss; ss << "recv MSG_FILE_FRAGMENT : " << std::endl;
                            main_global::log(ss.str());
						}

						NETW_MSG::MSG_FILE_FRAGMENT_HEADER mh;
						bool r = NETW_MSG::MSG::parse_file_fragment_header_from_msg(m, mh);
						if (r)
						{
							r = add_file_to_recv(mh.filename, mh.filename_key);
							if (r)
							{
								std::lock_guard lck(_map_file_to_recv_mutex);
								size_t idx_fragment;
								r = map_file_to_recv[mh.filename_key].add_recv_fragment_data(mh,
													m.buffer + NETW_MSG::MESSAGE_HEADER + mh.header_size(),
													m.buffer_len - (NETW_MSG::MESSAGE_HEADER + mh.header_size()), idx_fragment);
								if (r)
								{
									auto& binfile = map_file_to_recv[mh.filename_key];
									binfile.set_fragment_processed(idx_fragment, m.buffer_len - (NETW_MSG::MESSAGE_HEADER + mh.header_size()) );
									// save file if fully processed...
									ui_dirty = true;
								}
							}
						}
					}
                }

				std::memset(message_buffer, '\0', sizeof (message_buffer));
			}
			this->m_state = STATE::CLOSED;
		}));
	}

	void ysClient::client_UI()
	{
		int cnt = 0;
		std::string message = "";

		while (this->m_state == STATE::OPEN)
		{
			if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
			{
				std::stringstream ss; ss << " Exiting loop client_UI " << std::endl;
				main_global::log(ss.str(), true);
				break;
			}

			std::this_thread::sleep_for(std::chrono::seconds(1));

			if (cnt == 0)
			{
				//message = get_input("Send first msg to server to receive instructions");

				if (message.size() == 0) message = "hello";

				NETW_MSG::MSG m;
				m.make_msg(NETW_MSG::MSG_TEXT, message, getDEFAULT_KEY());
				this->sendMessageBuffer(this->m_socketFd, m, getDEFAULT_KEY());

				std::string s = m.get_data_as_string();
				add_to_history(false, NETW_MSG::MSG_TEXT, s);
				ui_dirty = true;

				//if (DEBUG_INFO)
				{
                    std::stringstream ss; ss << "send MSG_TEXT : " << message << std::endl;
                    main_global::log(ss.str());
				}
				cnt++;
			}

			if (key_valid && rnd_valid && user_valid)
			{
				main_client_ui(this);
			}
			else if (!user_valid)
			{

			}
			else if (key_valid || rnd_valid)
			{
				{
					message = get_input("Enter chat msg");

					std::string key;
					{
						std::lock_guard l(_key_mutex);
						if (!key_valid)
							key = getDEFAULT_KEY();
						else if (!rnd_valid)
							key = initial_key;
						else
							key = random_key;
					}

					NETW_MSG::MSG m;
					m.make_msg(NETW_MSG::MSG_TEXT, message, key);
					//if (DEBUG_INFO)
					{
                        std::stringstream ss; ss << "send MSG_TEXT : " << message << std::endl;
                        main_global::log(ss.str());
					}

					this->sendMessageBuffer(this->m_socketFd, m, key);

					std::string s = m.get_data_as_string();
					add_to_history(false, NETW_MSG::MSG_TEXT, s);
					ui_dirty = true;

					cnt++;
				}
			}
		}
	}

	ysClient::ysClient(cryptochat::cfg::cfg_cli cfg, const std::string& cfgfile) :
        ysNodeV4(cfg._port),
        m_serverName(cfg._server),
        _cfg_cli(cfg),
        _cfgfile(cfgfile)
	{
		setDefault();
	}

	void ysClient::setOnMessage(const std::function<void(const std::string&)>& t_function) {
		m_onMessage = t_function;
	}

	void ysClient::connectServer()
	{
		this->_connectServer();
		showMessage("Connection successfully....");

		this->recv_thread();
		this->send_pending_file_packet_thread();
		this->client_UI();
	}

	void ysClient::closeConnection() {
        std::cout << "closing socket" << std::endl;
        try{
            this->closeSocket();
		}
		catch(...)
		{
		}

		std::cout << "waiting recv thread ending " << std::endl;
		if (this->m_recv_thread.joinable()) {
			this->m_recv_thread.join();
		}

		std::cout << "waiting send thread ending " << std::endl;
		if (this->m_send_thread.joinable()) {
			this->m_send_thread.join();
		}
	}

	ysClient::~ysClient() {
        std::cout << "closing connection" << std::endl;
		this->closeConnection();
	}

}
