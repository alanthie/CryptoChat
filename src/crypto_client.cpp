/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <string>
#ifdef _WIN32
#include <conio.h>
#else
#endif

#include <stdlib.h>
#include <chrono>
#include <iostream>
#include <fstream>

#include "../include/crypto_const.hpp"
#include "../include/crypto_client.hpp"
#include "../include/crc32a.hpp"
#include "../include/Menu.h"
#include "../include/chat_cli.hpp" // std::atomic<int> cryptochat::cli::chat_cli::got_chat_cli_signal
#include "../include/main_global.hpp"
#include "../include/data.hpp"
#include "../include/challenge.hpp"
#include "../include/file_util.hpp"
#include "../include/encdec_algo.hpp"
#include "../include/machineid.h"

#include <ciso646>
#include <iostream>
#include <string>

extern int main_client_ui(crypto_socket::crypto_client* netw_client);

namespace crypto_socket {

	bool crypto_client::is_got_chat_cli_signal()
	{
		if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1) return true;
		return false;
	}

	void crypto_client::setDefault() {
		inet_pton(AF_INET, this->m_serverName.c_str(), &this->m_socketInfo.sin_addr);
	}

	void crypto_client::showMessage(const std::string& t_message) {
		if (this->m_onMessage != nullptr) {
			this->m_onMessage(t_message);
		}
	}

	void crypto_client::_connectServer() {
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
	void crypto_client::send_pending_file_packet_thread()
	{
		this->m_send_thread = std::move(std::thread([=, this]
		{
			while (true)
			{
				if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
				{
					std::stringstream ss;
					ss << "Exiting thread send_pending_file_packet_thread " << std::endl;
					main_global::log(ss.str());
					break;
				}

				std::string key = get_key();
				int send_status;
				bool r = send_next_pending_file_packet(this->m_socketFd, key, send_status);
				if (r)
                {
                    ui_dirty = true;
				}
				// send TXT msg...

				// sleep ...
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}));
	}

    std::string crypto_client::get_input(const std::string& q)
	{
		std::cout << q << ": ";
		std::string message;
		std::cin >> message;
		std::cout << std::endl;

		std::cin.ignore(0x7fffffffffffffff, '\n');
		std::cin.clear();

		return message;
	}

	// RECV THREAD
	void crypto_client::recv_thread()
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
			std::stringstream ss;
			while (msg_ok && this->m_state == STATE::OPEN)
			{
				recv_while_count1++;

				if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
				{
					ss << " Exiting thread recv_thread " << std::endl;
					main_global::log(ss.str());
					ss.clear();
					msg_ok = false;
					break;
				}

				if (byte_recv > 0)
				{
					memcpy(message_buffer, message_previous_buffer, byte_recv);
					ss<< "recv() bytes total " << byte_recv << std::endl;
				}

				while (byte_recv < NETW_MSG::MESSAGE_HEADER && msg_ok==true)
				{
					recv_while_count2++;

					if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
					{
						ss << " Exiting thread recv_thread " << std::endl;
						main_global::log(ss.str());
						ss.clear();
						msg_ok = false;
						break;
					}

					len = recv(this->m_socketFd, message_buffer + byte_recv, NETW_MSG::MESSAGE_HEADER - byte_recv, 0);
					if (len > 0)
					{
						byte_recv += len;
						cli_byte_recv = byte_recv;
						ss << "recv() bytes total " << byte_recv << std::endl;
						main_global::log(ss.str());
						ss.clear();
					}
					else
					{
						if (len == 0)
							ss << "WARNING recv() - socket closed" << std::endl;
						else
							ss << "WARNING recv() - socket error" << std::endl;
						msg_ok = false;
						main_global::log(ss.str());
						ss.clear();
						break;
					}
				}

				expected_len = NETW_MSG::MSG::byteToUInt4(message_buffer + 1);

				cryptoAL::cryptodata recv_buffer; // new instance ...use reset TODO
				if (byte_recv > 0)
				{
					recv_buffer.buffer.write(message_buffer, byte_recv);
				}

				size_t len_recv_buffer_call = 0;
				while (byte_recv < expected_len && msg_ok==true)
				{
					recv_while_count3++;

					if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
					{
						ss << " Exiting thread recv_thread " << std::endl;
						main_global::log(ss.str());
						ss.clear();
						msg_ok = false;
						break;
					}

					len_recv_buffer_call = expected_len - byte_recv;
					if (len_recv_buffer_call > NETW_MSG::MESSAGE_SIZE) len_recv_buffer_call = NETW_MSG::MESSAGE_SIZE;

					len = recv(this->m_socketFd, message_buffer, len_recv_buffer_call, 0);
					if (len > 0)
					{
						byte_recv += len;
						cli_byte_recv = byte_recv;
						recv_buffer.buffer.write(message_buffer, len);
						ss << "recv() bytes total " << byte_recv << std::endl;
						main_global::log(ss.str());
						ss.clear();
					}
					else
					{
						std::stringstream ss;
						if (len == 0)
							ss << "WARNING recv() - socket closed" << std::endl;
						else
							ss << "WARNING recv() - socket error" << std::endl;
						msg_ok = false;
						main_global::log(ss.str());
						ss.clear();
						break;
					}
				}

				if (msg_ok)
				{
					if (byte_recv >= expected_len)
					{
						byte_recv = byte_recv - expected_len;
						if (byte_recv > 0)
						{
							if (byte_recv <= NETW_MSG::MESSAGE_SIZE)
								memcpy(message_previous_buffer, message_buffer, byte_recv);
							else
							{
                                // not possible...
								ss << "WARNING recv() - excess data recv" << byte_recv << std::endl;
								main_global::log(ss.str());
                                ss.clear();
							}
						}
					}
				}

				if (!msg_ok)
				{
					break;
				}

				uint8_t original_flag = recv_buffer.buffer.getdata()[NETW_MSG::MESSAGE_FLAG_START];
				uint32_t from_user	= NETW_MSG::MSG::byteToUInt4((char*)recv_buffer.buffer.getdata() + NETW_MSG::MESSAGE_FROM_START);
				uint32_t to_user	= NETW_MSG::MSG::byteToUInt4((char*)recv_buffer.buffer.getdata() + NETW_MSG::MESSAGE_TO_START);

				{
					std::stringstream ss;
					ss << "recv msg"
						<< " type:" << std::to_string((int)recv_buffer.buffer.getdata()[0])
						<< " crypto:" << std::to_string((int)original_flag)
						<< " from_user: " << from_user
						<< " to_user: " << to_user
						<< " len: " << expected_len
						<< std::endl;
					main_global::log(ss.str());
					ss.clear();
				}

				bool r = true;
				NETW_MSG::MSG m;
				NETW_MSG::MSG msgout;

				//-----------------------------------------------
				// Parse message
				//	call make_decrypt_msg()
				// 	call crypto_decrypt()
				//-----------------------------------------------
				if (r == true)
				{
					{
						std::lock_guard l(_key_mutex);

						if (!key_valid)	        r = m.parse((char*)(char*)recv_buffer.buffer.getdata(), expected_len, getDEFAULT_KEY());
						else if (!rnd_valid)    r = m.parse((char*)(char*)recv_buffer.buffer.getdata(), expected_len, get_initial_key64());
						else                    r = m.parse((char*)(char*)recv_buffer.buffer.getdata(), expected_len, random_key, previous_random_key, pending_random_key);
					}

					if (original_flag > 0) // crypto flag
					{
						r = crypto_decrypt(from_user, to_user, (char*)m.buffer, m.buffer_len, msgout);

						if (!r)
						{
							ss << "WARNING - Failed to decrypt recv message" << std::endl;
							main_global::log(ss.str());
                            ss.clear();
						}
						else
						{
							{
								ss << "crypto_decrypt ok, msg len: " << msgout.buffer_len << std::endl;
								main_global::log(ss.str());
                                ss.clear();
							}

							m.reset();
							m.make_msg(msgout.buffer, msgout.buffer_len);
						}
					}

					std::string str_message = m.get_data_as_string();

                    if (m.type_msg == NETW_MSG::MSG_CMD_REQU_SHUTDOWN)
                    {
                    	{
							ss << "recv MSG_CMD_REQU_SHUTDOWN" << std::endl;
							main_global::log(ss.str());
                            ss.clear();
						}

                        std::string key = get_key();
                        msg_ok = false;
                        cryptochat::cli::chat_cli::got_chat_cli_signal = 1;
                        //main_global::shutdown(); // thread will join on itself = bug

                        // socked should stop after next send or recv
                        NETW_MSG::MSG m;
						m.make_msg(NETW_MSG::MSG_CMD_RESP_SHUTDOWN, "shutdown", key);
						send_message_buffer(this->m_socketFd, m, key);
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_KEY_HINT)
                    {
                        challenge_attempt++;
						{
							ss << "recv MSG_CMD_REQU_KEY_HINT" << std::endl;
							main_global::log(ss.str());
							ss.clear();
						}

						if (_cfg_cli.map_challenges.contains(str_message))
						{
							ss << "using known challenge answer" << std::endl;
							ss << "send MSG_CMD_RESP_KEY_HINT" << std::endl;

							{
								std::lock_guard l(_key_mutex);
								initial_key_hint = str_message;
								initial_key = _cfg_cli.map_challenges[str_message]; // but key_valid = false until confirmed
								initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
							}
							ss << "initial_key_hint set" << std::endl;
							main_global::log(ss.str());
							ss.clear();

							NETW_MSG::MSG m;
							m.make_msg(NETW_MSG::MSG_CMD_RESP_KEY_HINT, _cfg_cli.map_challenges[str_message], getDEFAULT_KEY());
							this->send_message_buffer(this->m_socketFd, m, getDEFAULT_KEY());
						}
						else
						{
							std::string work = str_message;
							std::vector<std::string> lines = NETW_MSG::split(work, "\n");
							std::vector<std::string> comments;
							std::vector<std::string> questions;
							std::vector<int> question_types;
							for (size_t i = 0; i < lines.size(); i++)
							{
								if (lines[i][0] == 'C')
									comments.push_back(lines[i].substr(1, lines[i].size() - 1));
								else if (lines[i][0] == 'F')
								{
									questions.push_back(lines[i].substr(1, lines[i].size() - 1));
									question_types.push_back(1);
								}
								else if (lines[i][0] == 'T')
								{
									questions.push_back(lines[i].substr(1, lines[i].size() - 1));
									question_types.push_back(0);
								}
							}

							std::vector< std::string> a;
							for (size_t i = 0; i < questions.size(); i++) a.push_back({});

							bool menu_abort = false;
							while (true)
							{
								if (is_got_chat_cli_signal())
								{
									ss << "Terminating menu" << std::endl;
									main_global::log(ss.str());
									ss.clear();
									menu_abort = true;
									break;
								}

								Menu qa;
								qa.set_heading(std::string("Challenges (q TO QUIT MENU)")
									+ std::string(" [Attempt: ") + std::to_string(challenge_attempt) + "]",
									comments);

								qa.set_max_len(120);
								for (size_t i = 0; i < questions.size(); i++)
									qa.add_field(std::string("[" + std::to_string(i + 1) + "] ") + questions[i] + " : " + a[i], nullptr);

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
									a[idx] = get_input("Enter answer [" + std::to_string(idx + 1) + "]");
								}
							}

							if (!menu_abort)
							{
								std::string r;
								for (size_t i = 0; i < questions.size(); i++)
								{
									if (question_types[i] == 1)
									{
										std::string out_answer;
										std::string out_error;
										bool r = NETW_MSG::challenge_answer(a[i], out_answer, out_error);
										if (r)
										{
											a[i] = out_answer;
										}
									}
									r += a[i];
								}

								{
									{
										ss << "recv MSG_CMD_REQU_KEY_HINT" << std::endl;
										main_global::log(ss.str());
										ss.clear();
									}

									{
										std::lock_guard l(_key_mutex);
										initial_key_hint = str_message;
										initial_key = r; // but key_valid = false until confirmed
										initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
									}

									ss << "initial_key_hint set size=" << initial_key_hint.size() << std::endl;

                                    ss << "send MSG_CMD_RESP_KEY_HINT" << std::endl;
                                    main_global::log(ss.str());
                                    ss.clear();

									NETW_MSG::MSG m;
									m.make_msg(NETW_MSG::MSG_CMD_RESP_KEY_HINT, r, getDEFAULT_KEY());
									this->send_message_buffer(this->m_socketFd, m, getDEFAULT_KEY());
								}
							}
						}
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_VALID)
                    {
                        {
							ss << "recv MSG_CMD_INFO_KEY_VALID" << std::endl;

                            // CONFIRMED new key
                            key_valid = true;
							if (initial_key_hint.size() > 0)
							{
								std::string serr;
								_cfg_cli.map_challenges[initial_key_hint] = initial_key;

								ss << "saving challenge answer" << std::endl;
								bool ret = _cfg_cli.save_cfg(_cfgfile, serr);
								if (ret == false)
								{
									ss << serr;
								}

								initial_key64 = initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
							}
							else
							{
								ss << "WARNING initial_key_hint empty" << std::endl;
							}
							main_global::log(ss.str());
							ss.clear();

                            showMessage(str_message);
                            add_to_history(true, NETW_MSG::MSG_CMD_INFO_KEY_VALID, str_message);
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_INVALID)
                    {
                        {
                            ss << "recv MSG_CMD_INFO_KEY_INVALID" << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
                        }

                        key_valid = false;

                        showMessage(str_message);
                        add_to_history(true, NETW_MSG::MSG_CMD_INFO_KEY_INVALID, str_message);
                    }
					else if (m.type_msg == NETW_MSG::MSG_CMD_ACCEPT_USERNAME)
					{
						ss << "recv MSG_CMD_ACCEPT_USERNAME " << str_message << std::endl;
						this->username = str_message;

						if (map_user_index_to_user.contains(my_user_index))
						{
							std::string h;
							char host[80] = { 0 };
							if (gethostname(host, 80) == 0)
							{
								h = std::string(host);
								this->hostname = h;
							}

							userinfo ui;
							ui.host = h;
							ui.usr = str_message;
							map_user_index_to_user[user_index] = ui;
							set_user_view_dirty(true);
						}
						main_global::log(ss.str());
						ss.clear();
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

                        ss << "recv MSG_CMD_REQU_ACCEPT_RND_KEY" << std::endl;

						if (DEBUG_INFO)
                        {
							ss << "Random key recv ["
                                + file_util::get_summary_hex((char*)work.data(), work.size()) + "]" << std::endl;

                            ss << "Random key digest recv [" + str_digest + "]" << std::endl;

                            CRC32 chk;
                            chk.update((char*)work.data(), work.size());
							ss << "Random key CRC32 recv [" << chk.get_hash() << "]" << std::endl;
                        }
                        main_global::log(ss.str());
                        ss.clear();

						std::string key = get_key();

						{
                            ss << "send MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
						}

						NETW_MSG::MSG m;
                        m.make_msg(NETW_MSG::MSG_CMD_RESP_ACCEPT_RND_KEY, str_digest, key);
                        this->send_message_buffer(this->m_socketFd, m, key);
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_RND_KEY_VALID)
                    {
                        {
							{
                                ss << "recv MSG_CMD_INFO_RND_KEY_VALID" << std::endl;
                                main_global::log(ss.str());
                                ss.clear();
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
						{
                            ss << "recv MSG_CMD_REQU_USERNAME" << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
						}

                        if (_cfg_cli._username.size() == 0)
                        {
                            showMessage(str_message);
                            std::string r = get_input("Enter username");
                            if (r.size() == 0) r = "user_xyz"; // TODO validate
                            _cfg_cli._username = r;

							std::string serr;
							bool ret =  _cfg_cli.save_cfg(_cfgfile, serr);
							if (!ret)
							{
								ss <<  serr << std::endl;
								main_global::log(ss.str());
								ss.clear();
							}
                        }
                        user_valid = true;

						{
							ss << "send MSG_CMD_RESP_USERNAME : " << _cfg_cli._username << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
						}

                        NETW_MSG::MSG m;
                        std::string key = get_key();

                        m.make_msg(NETW_MSG::MSG_CMD_RESP_USERNAME, _cfg_cli._username, key);
                        this->send_message_buffer(this->m_socketFd, m, key);
                    }
					else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_HOSTNAME)
					{
						{
                            ss << "recv MSG_CMD_REQU_HOSTNAME" << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
						}

						char host[80] = { 0 };
						if (gethostname(host, 80) == 0)
						{
							std::string h = std::string(host);
							this->hostname = h;

							{
                                ss << "send MSG_CMD_RESP_HOSTNAME : " << h << std::endl;
								main_global::log(ss.str());
								ss.clear();
							}

							NETW_MSG::MSG m;
							std::string key = get_key();

							m.make_msg(NETW_MSG::MSG_CMD_RESP_HOSTNAME, h, key);
							this->send_message_buffer(this->m_socketFd, m, key);
						}
						else
						{
							ss << "WARNING gethostname failed" << std::endl;
							main_global::log(ss.str());
							ss.clear();
						}
					}
					else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_MACHINEID)
					{
						{
                            ss << "recv MSG_CMD_REQU_MACHINEID" << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
						}

						//-------------------------------------------
						// my_machineid
						//-------------------------------------------
						std::string my_machineid = machineid::machineHash();
						this->machine_id = my_machineid;

						{
							{
                                ss << "send MSG_CMD_RESP_MACHINEID : " << my_machineid << std::endl;
                                main_global::log(ss.str());
                                ss.clear();
							}

							NETW_MSG::MSG m;
							std::string key = get_key();

							m.make_msg(NETW_MSG::MSG_CMD_RESP_MACHINEID, my_machineid, key);
							std::stringstream serr;
							this->send_composite(this->m_socketFd, m, key, serr);
							main_global::log(serr.str());
							ss.clear();
						}
					}
					else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_USERINDEX)
					{
						{
							ss << "recv MSG_CMD_INFO_USERINDEX " << str_message << std::endl;
							main_global::log(ss.str());
							ss.clear();
						}

						//-------------------------------------------
						// my_user_index
						//-------------------------------------------
						my_user_index = (uint32_t)NETW_MSG::str_to_ll(str_message);

						{
							ss << "My USERINDEX set to " << str_message << std::endl;
							main_global::log(ss.str());
							ss.clear();
						}

					}
					else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_USERLIST)
					{
						{
							ss << "recv MSG_CMD_INFO_USERLIST : " << std::endl;
							ss << "     " << str_message << std::endl;
							main_global::log(ss.str());
							ss.clear();
						}

						//s = v_client[i]->std::to_string(v_client[i]->user_index) + ";" + v_client[i]->hostname + ";" + v_client[i]->username + ";";
						std::string work = str_message;
						std::vector<std::string> tokens = NETW_MSG::split(work, ";");

						uint32_t user_index;
						std::string in_host;
						std::string in_usr;

						int cnt = 0;
						for (size_t i = 0; i < tokens.size(); i++)
						{
							if (cnt == 0)
							{
								user_index = (uint32_t)NETW_MSG::str_to_ll(tokens[i]);
							}
							else if (cnt == 1) in_host = tokens[i];
							else if (cnt == 2) in_usr = tokens[i];

							if (cnt == 2)
							{
								if (user_index > 0 && in_host.size() > 0 && in_usr.size() > 0)
									handle_info_client(user_index, in_host, in_usr);
							}
							cnt++;
							if (cnt >= 3) cnt = 0;
						}

					}
                    else if (m.type_msg == NETW_MSG::MSG_TEXT)
                    {
						{
							ss << "recv MSG_TEXT : " << str_message << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
						}

                        showMessage(str_message);
                        add_to_history(true, NETW_MSG::MSG_TEXT, str_message);
                        ui_dirty = true;
                    }

					else if (m.type_msg == NETW_MSG::MSG_FILE)
					{
						{
                            ss << "recv MSG_FILE : " << str_message << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
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
						{
                            ss << "recv MSG_FILE_FRAGMENT : " << std::endl;
                            main_global::log(ss.str());
                            ss.clear();
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

				//std::memset(message_buffer, '\0', sizeof (message_buffer));
			}

			{
                ss << "recv thread done"<< std::endl;
                main_global::log(ss.str());
                ss.clear();
			}
			this->m_state = STATE::CLOSED;
		}));
	}


	void crypto_client::handle_info_client(uint32_t user_index, const std::string& in_host, const std::string& in_usr)
	{
		bool changed = false;
		std::stringstream ss;
		if (map_user_index_to_user.contains(user_index) == false)
		{
			userinfo ui;
			ui.host = in_host;
			ui.usr = in_usr;
			map_user_index_to_user[user_index] = ui;
			set_user_view_dirty(true);
			changed = true;

			ss << "New user added to active user list " << user_index << " " << in_host << " " << in_usr << std::endl;
			main_global::log(ss.str());
		}
		else
		{
			if (in_host.size() > 0 && map_user_index_to_user[user_index].host.size() == 0)
			{
				map_user_index_to_user[user_index].host = in_host;
				changed = true;
			}
			if (in_usr.size() > 0 && map_user_index_to_user[user_index].usr.size() == 0)
			{
				map_user_index_to_user[user_index].usr = in_usr;
				changed = true;
			}
		}
		if (changed)
			handle_new_client(user_index, in_host, in_usr);
	}

	void crypto_client::handle_new_client(uint32_t user_index, const std::string& in_host, const std::string& in_usr)
	{
		bool r = false;
		std::stringstream ss;
		std::string serr;

		ss << "handle_new_client " << user_index << " " << in_host << " " << in_usr<<std::endl;

		if (repository_root_set && user_index > 0 && user_index == my_user_index) // prevent multi instance file contention
		{
			r = _repository.user_exist(user_index, in_host, in_usr);
			if (r == false)
			{
				r = _repository.add_user(user_index, in_host, in_usr, serr);
				if (r)
				{
					ss << "INFO - New user add to repository " << user_index << std::endl;
					ss << serr << std::endl;
				}
				else
				{
					// multi instance...
					if (_repository.user_exist(user_index, in_host, in_usr) == false)
					{
						ss << "WARNING - Failed to add user to repository " << user_index << std::endl;
						ss << serr << std::endl;
					}
				}
			}
		}

		if (repository_root_set && user_index > 0)
		{
			r = _repository.user_exist(user_index, in_host, in_usr);
			if (r == true)
			{
				cryptochat::cfg::cfg_crypto cc;
				if (map_active_user_to_crypto_cfg.contains(user_index) == false)
				{
					std::string inifile = _repository.get_crypto_cfg_filename(user_index);
					if (!inifile.empty())
					{
						r = cc.read(inifile, serr, false);
						if (r)
						{
							map_active_user_to_crypto_cfg[user_index] = cc._p;
						}
						else
						{
							ss << "WARNING - cannot read crypto_cfg " << inifile << std::endl;
						}
					}
					else
					{
						r = false;
						ss << "WARNING - no crypto_cfg file " << inifile << std::endl;
					}
				}

				{
					if (map_active_user_to_urls.contains(user_index) == false)
					{
						map_active_user_to_urls[user_index] = cc._p.filename_urls;
					}
				}
			}
		}
		main_global::log(ss.str());
	}

	void crypto_client::client_UI()
	{
		int cnt = 0;
		std::string message = "";

		while (this->m_state == STATE::OPEN)
		{
			if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
			{
				std::stringstream ss;
				ss << " Exiting loop client_UI " << std::endl;
				main_global::log(ss.str());
				break;
			}

			std::this_thread::sleep_for(std::chrono::seconds(1));

			if (cnt == 0)
			{
				if (message.size() == 0) message = "hello";

				NETW_MSG::MSG m;
				std::stringstream serr;

				m.make_msg(NETW_MSG::MSG_TEXT, message, getDEFAULT_KEY());
				this->send_composite(this->m_socketFd, m, getDEFAULT_KEY(), serr);

				std::string s = m.get_data_as_string();
				add_to_history(false, NETW_MSG::MSG_TEXT, s);
				ui_dirty = true;

				serr << "send MSG_TEXT : " << message << std::endl;

				cnt++;
				main_global::log(serr.str());
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
					std::stringstream serr;
					message = get_input("Enter chat msg");

					std::string key = get_key();

					NETW_MSG::MSG m;
					m.make_msg(NETW_MSG::MSG_TEXT, message, key);

					serr << "send MSG_TEXT : " << message << std::endl;
					this->send_composite(this->m_socketFd, m, key, serr);

					std::string s = m.get_data_as_string();
					add_to_history(false, NETW_MSG::MSG_TEXT, s);
					ui_dirty = true;

					cnt++;
					main_global::log(serr.str());
				}
			}
		}
	}

	crypto_client::crypto_client(cryptochat::cfg::cfg_cli cfg, const std::string& cfgfile) :
		client_node(cfg._port),
        m_serverName(cfg._server),
        _cfg_cli(cfg),
        _cfgfile(cfgfile)
	{
		setDefault();

		std::string serr;
		if (_repository.set_root(_cfg_cli._repo_root_path, serr) == false)
		{
			repository_root_set = false;

			std::stringstream ss;
			ss << serr << std::endl;
            main_global::log(ss.str());
		}
		else
		{
			repository_root_set = true;

			std::stringstream ss;
			ss << "INFO - Repository path set to : " << _cfg_cli._repo_root_path << std::endl;
			main_global::log(ss.str());
		}

		cryptoAL::encryptor* _encryptor = nullptr;
		cryptoAL::decryptor* _decryptor = nullptr;
	}

	void crypto_client::setOnMessage(const std::function<void(const std::string&)>& t_function) {
		m_onMessage = t_function;
	}

	void crypto_client::connectServer()
	{
		this->_connectServer();
		showMessage("Connection successfully....");

		this->recv_thread();
		this->send_pending_file_packet_thread();
		this->client_UI();
	}

	void crypto_client::closeConnection() {
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

	crypto_client::~crypto_client()
	{
        std::cout << "~crypto_client -closing connection" << std::endl;
		this->closeConnection();

		if (_encryptor != nullptr) delete _encryptor;
		if (_decryptor != nullptr) delete _decryptor;
	}


	bool crypto_client::add_file_to_send(const std::string& filename, const std::string& filename_key)
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
	bool crypto_client::add_file_to_recv(const std::string& filename, const std::string& filename_key)
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

	bool crypto_client::get_info_file_to_send(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done)
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
	bool crypto_client::get_info_file_to_recv(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done)
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

	std::string crypto_client::get_file_to_send(const std::string& filename_key)
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
	std::string crypto_client::get_file_to_recv(const std::string& filename_key)
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

	bool crypto_client::send_next_pending_file_packet(const int& t_socketFd, const std::string& key, int& send_status)
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
				// TODO add flag, user...
				uint8_t crypto_flag = 1;
				if (chat_with_other_user_index == 0) crypto_flag = 0;
				send_status = send_message_buffer(	t_socketFd, m, key,
													crypto_flag,
													my_user_index,
													chat_with_other_user_index);

				//send_status = send_message_buffer(t_socketFd, m, key);
				msg_sent = true;
				ui_dirty = true;
			}
		}

		return msg_sent;
	}

	// called when new message received and crypto flag on
	bool crypto_client::crypto_decrypt(uint32_t from_user, uint32_t to_user, char* buffer, uint32_t buffer_len, NETW_MSG::MSG& msgout)
	{
		bool r = false;
		std::stringstream ss;

		if (repository_root_set == false)
		{
            ss << "WARNING crypto_decrypt() - repository_root_set == false)" << std::endl;
            main_global::log(ss.str());
			return false;
        }

		if (DEBUG_INFO)
        {
            ss << "crypto_decrypt(...)" << std::endl;
			ss << "crypto_decrypt msgin.buffer_len: " << buffer_len << std::endl;
        }

		if (from_user == 0) // crypto is between two specific user
		{
            ss << "WARNING crypto_decrypt - invalid user from_user==0 - msg not decrypted" << std::endl;
		}

		if (to_user != my_user_index)
		{
			ss << "WARNING crypto_decrypt - from_user != my_user_index" << std::endl;
		}

		if (from_user > 0 && to_user == my_user_index)
		{
			std::string s;
			if (map_active_user_to_crypto_cfg.contains(from_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(from_user);
				if (!inifile.empty())
				{
					cryptochat::cfg::cfg_crypto cc;
					r = cc.read(inifile, s, false);
					if (r)
					{
						map_active_user_to_crypto_cfg[from_user] = cc._p;
					}
					else
					{
						ss << "WARNING - crypto_decrypt - cannot read crypto_cfg " << inifile << std::endl;
					}
				}
			}

			if (map_active_user_to_urls.contains(from_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(from_user);
				cryptochat::cfg::cfg_crypto cc;
				r = cc.read(inifile, s, false);
				if (r)
				{
					map_active_user_to_urls[from_user] = cc._p.filename_urls;
				}
				else
				{
					ss << "WARNING - crypto_decrypt - cannot read crypto_cfg " << inifile << std::endl;
				}
			}

			if (map_active_user_to_crypto_cfg.contains(from_user) && map_active_user_to_urls.contains(from_user))
			{
				// content to decrypt is past the header
				cryptoAL::cryptodata din;
				din.buffer.write(buffer + NETW_MSG::MESSAGE_HEADER, buffer_len - NETW_MSG::MESSAGE_HEADER);
				std::string user_folder = _repository.get_user_folder(from_user) + cryptochat::db::Repository::file_separator();
				bool r = din.save_to_file(user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_encrypted_data);

				if (DEBUG_INFO)
					ss << "crypto_decrypt filename_encrypted_data.buffer.size(): " << din.buffer.size() << std::endl;

				if (r)
				{
					if (_decryptor != nullptr)
					{
						delete _decryptor;
						_decryptor = nullptr;
					}

					// try catch...
					_decryptor = new cryptoAL::decryptor(
						{},
						{}, // filename_puzzle
						user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_encrypted_data,
						user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_decrypted_data,
						{}, // staging
						map_active_user_to_crypto_cfg[from_user].folder_local,
						map_active_user_to_crypto_cfg[from_user].folder_my_private_rsa,
						map_active_user_to_crypto_cfg[from_user].folder_other_public_rsa,
						map_active_user_to_crypto_cfg[from_user].folder_my_private_ecc,
						map_active_user_to_crypto_cfg[from_user].folder_other_public_ecc,
						map_active_user_to_crypto_cfg[from_user].folder_my_private_hh,
						map_active_user_to_crypto_cfg[from_user].folder_other_public_hh,
						map_active_user_to_crypto_cfg[from_user].wbaes_my_private_path,
						map_active_user_to_crypto_cfg[from_user].wbaes_other_public_path,
						false,                      // Flag - verbose
						false,                      // Flag - keep staging files
						map_active_user_to_crypto_cfg[from_user].encryped_ftp_user,
						map_active_user_to_crypto_cfg[from_user].encryped_ftp_pwd,
						map_active_user_to_crypto_cfg[from_user].known_ftp_server,
						true,	// use_gmp,
						map_active_user_to_crypto_cfg[from_user].auto_flag,	// autoflag
						false	//converter
					);
				}
				else
				{
                    {
                        ss  << "WARNING crypto_decrypt - invalid file "
                            << user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_encrypted_data << std::endl;
                    }
				}

				if (r)
				{
					std::ofstream out(user_folder + cryptochat::db::Repository::file_separator() +"cout_decrypt.txt");
					auto* coutbuf = std::cout.rdbuf();
					std::cout.rdbuf(out.rdbuf());

					r = _decryptor->decrypt(ss);

					std::cout.rdbuf(coutbuf);

					if (r)
					{
						cryptoAL::cryptodata dout;
						r = dout.read_from_file(user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_decrypted_data);
						if (r)
						{
							//if (DEBUG_INFO)
                            {
								ss << "CRYPTO decryption ok" << std::endl;
								ss << "crypto_decrypt filename_decrypted_data.buffer.size(): " << dout.buffer.size() << std::endl;
                            }

							// un padding ????
							// MSG = MESSAGE_HEADER + data + [____pad_end_number(1-64)]
							//uint32_t padding = (uint32_t)dout.buffer.getdata()[dout.buffer.size() - 1];
							//dout.buffer.remove_last_n_char(padding);

							////if (DEBUG_INFO)
							//{
							//	ss << "un padding: " << padding << std::endl;
							//	ss << "crypto_decrypt filename_decrypted_data.buffer.size(): " << dout.buffer.size() << std::endl;
							//}

							// original header
							uint8_t digestkey[32];
							memcpy(&digestkey[0], buffer + NETW_MSG::MESSAGE_KEYDIGEST_START, 32);

							uint8_t chk[4];
							memcpy(&chk[0], buffer + NETW_MSG::MESSAGE_CRC_START, 4);
							uint32_t crc = NETW_MSG::MSG::byteToUInt4((char*)buffer + NETW_MSG::MESSAGE_CRC_START);

							msgout.make_msg_with_crc_and_flag_buffer(
								buffer[0], dout.buffer.size(), (uint8_t*)dout.buffer.getdata(), digestkey, crc, 0, from_user, to_user);

							main_global::log(ss.str());
                            return true;
						}
						else
						{
						    {
                                ss << "WARNING crypto_decrypt - invalid file "
                                << user_folder + map_active_user_to_crypto_cfg[from_user].filename_decrypted_data<<std::endl;
                            }
						}
					}
					else
                    {
                        {
                            ss << "WARNING crypto_decrypt - decryptor->decrypt() failed" << std::endl;
                        }
                    }
				}
			}
			else
            {
                ss << "WARNING crypto_decrypt - no (map_active_user_to_crypto_cfg.contains(from_user) && map_active_user_to_urls.contains(from_user))" << std::endl;
            }
		}
		main_global::log(ss.str());
		return r;
	}

    int crypto_client::send_message_buffer(const int& t_socketFd, NETW_MSG::MSG& msgin, std::string key,
                                            uint8_t crypto_flag, uint8_t from_user, uint8_t to_user )
    {
        bool ok = true;
		std::stringstream ss;

		if (crypto_flag > 0 && to_user == 0)
		{
			ss << "WARNING - send_message_buffer - CRYPTO encryption with to_user==0 " << std::endl;
			ok = false;
		}

        if (crypto_flag > 0 && ok)
        {
            NETW_MSG::MSG msgout;
            bool r = crypto_encrypt(from_user, to_user, msgin, msgout);

            if (r)
            {
				auto ret = send_composite(t_socketFd, msgout, key, ss, crypto_flag, from_user, to_user );
				main_global::log(ss.str());
				return ret;
            }
            else
            {
                // SKIP crypto encryption on error (urls keys may be empty, ...)
                ss << "WARNING - CRYPTO encryption FAILED  - skipping encryption" << std::endl;
                crypto_flag = 0;
            }
        }

        if (ok)
        {
            auto ret = send_composite(t_socketFd, msgin, key, ss, crypto_flag, from_user, to_user );
			main_global::log(ss.str());
			return ret;
        }

		main_global::log(ss.str());
		return 0;
    }

	bool crypto_client::crypto_encrypt(uint32_t from_user, uint32_t to_user, NETW_MSG::MSG& msgin, NETW_MSG::MSG& msgout)
	{
		bool r = false;
		if (repository_root_set == false)
			return false;

		std::stringstream ss;
		if (to_user == 0)
		{
			ss << "WARNING crypto_encrypt - to_user==0 " << std::endl;
		}

		if (from_user != my_user_index)
		{
			ss << "WARNING crypto_encrypt - from_user != my_user_index" << std::endl;
		}

		if (to_user > 0 && from_user == my_user_index)
		{
            if (DEBUG_INFO)
                ss << "crypto_encrypt - msgin len " << msgin.buffer_len << std::endl;

			std::string s;
			if (map_active_user_to_crypto_cfg.contains(to_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(to_user);
				if (!inifile.empty())
				{
					cryptochat::cfg::cfg_crypto cc;
					r = cc.read(inifile, s, false);
					if (r)
					{
						map_active_user_to_crypto_cfg[to_user] = cc._p;
					}
					else
					{
						ss << "WARNING - cannot read crypto_cfg " << inifile << std::endl;
					}
				}
			}

			if (map_active_user_to_urls.contains(to_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(to_user);
				cryptochat::cfg::cfg_crypto cc;
				r = cc.read(inifile, s, false);
				if (r)
				{
					map_active_user_to_urls[to_user] = cc._p.filename_urls;
				}
				else
				{
					ss << "WARNING - cannot read crypto_cfg " << inifile << std::endl;
				}
			}

			if (map_active_user_to_crypto_cfg.contains(to_user) && map_active_user_to_urls.contains(to_user))
			{
				std::string msg_input = msgin.get_data_as_string();
				cryptoAL::cryptodata din;
				din.buffer.write(msg_input.data(), msg_input.size());

				std::string user_folder = _repository.get_user_folder(to_user) + cryptochat::db::Repository::file_separator();
				bool r = din.save_to_file(user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data);

				if (DEBUG_INFO)
                    ss << "crypto_encrypt - msgin without header  " << msg_input.size() << std::endl;

				if (r)
				{
					// padding
					uint32_t len_data = din.buffer.size();
					uint32_t padding = NETW_MSG::MESSAGE_FACTOR - (len_data % NETW_MSG::MESSAGE_FACTOR); // 0-63
					if (padding == 0) padding = 64;
					char cpadding = (char)(uint8_t)padding;
					char space[1]{ ' ' };
					for (int i = 0; i < padding - 1; i++) din.buffer.write(&space[0], 1);
					din.buffer.write(&cpadding, 1);

					if (DEBUG_INFO)
						ss << "crypto_encrypt padding: :" << padding << std::endl;

					bool r = din.save_to_file(user_folder + map_active_user_to_crypto_cfg[to_user].filename_msg_data);

					if (DEBUG_INFO)
						ss << "crypto_encrypt filename_msg_data.buffer.size(): " << din.buffer.size() << std::endl;
                    if (DEBUG_INFO)
                        ss << "crypto_encrypt - padding " << padding << std::endl;

					if (_encryptor != nullptr)
					{
						delete _encryptor;
						_encryptor = nullptr;
					}

					// try catch...
					_encryptor = new cryptoAL::encryptor(
						{},
						user_folder + map_active_user_to_urls[to_user],
						user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data,
						{}, // user_folder + map_active_user_to_crypto_cfg[to_user].filename_full_puzzle,
						{}, // map_active_user_to_crypto_cfg[to_user].filename_partial_puzzle,
						{}, // user_folder + map_active_user_to_crypto_cfg[to_user].filename_full_puzzle,
						user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data,
						{}, // map_active_user_to_crypto_cfg[to_user].staging,
						map_active_user_to_crypto_cfg[to_user].folder_local,
						map_active_user_to_crypto_cfg[to_user].folder_my_private_rsa,
						map_active_user_to_crypto_cfg[to_user].folder_other_public_rsa,
						map_active_user_to_crypto_cfg[to_user].folder_my_private_ecc,
						map_active_user_to_crypto_cfg[to_user].folder_other_public_ecc,
						map_active_user_to_crypto_cfg[to_user].folder_my_private_hh,
						map_active_user_to_crypto_cfg[to_user].folder_other_public_hh,
						map_active_user_to_crypto_cfg[to_user].wbaes_my_private_path,
						map_active_user_to_crypto_cfg[to_user].wbaes_other_public_path,
						false,                      // Flag - verbose
						false,                      // Flag - keep staging files
						map_active_user_to_crypto_cfg[to_user].encryped_ftp_user,
						map_active_user_to_crypto_cfg[to_user].encryped_ftp_pwd,
						map_active_user_to_crypto_cfg[to_user].known_ftp_server,
						1,		// map_active_user_to_crypto_cfg[to_user].key_size_factor,          // Parameter - keys size multiplier
						true,	// map_active_user_to_crypto_cfg[to_user].use_gmp,                  // Flag - use gmp for big computation
						false,	// map_active_user_to_crypto_cfg[to_user].self_test,                // Flag - verify encryption
						0,		// map_active_user_to_crypto_cfg[to_user].shufflePerc,              // Parameter - shuffling percentage
						map_active_user_to_crypto_cfg[to_user].auto_flag,	// autoflag
						0 //map_active_user_to_crypto_cfg[to_user].converter
					);
				}
				else
                {
                    {
                        ss << "WARNING crypto_encrypt - invalid file "
							<< user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data<<std::endl;
                    }
                }

				if (r)
				{
					/** backup cout buffer and redirect to out.txt **/
					std::ofstream out(user_folder + cryptochat::db::Repository::file_separator() + "cout_encrypt.txt");

					auto* coutbuf = std::cout.rdbuf();
					std::cout.rdbuf(out.rdbuf());

					r = _encryptor->encrypt(ss, true);

					std::cout.rdbuf(coutbuf);

					if (r)
					{
						cryptoAL::cryptodata dout;
						r = dout.read_from_file(user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data);
						if (r)
						{
							if (DEBUG_INFO)
								ss << "crypto_encrypt filename_encrypted_data.buffer.size(): " << dout.buffer.size() << std::endl;

                            if (DEBUG_INFO)
                                ss << "crypto_encrypt - msg encrypted len " << dout.buffer.size() << std::endl;

							// original header
							uint8_t digestkey[32];
							memcpy(&digestkey[0], msgin.buffer + NETW_MSG::MESSAGE_KEYDIGEST_START, 32);

							uint8_t chk[4];
							memcpy(&chk[0], msgin.buffer + NETW_MSG::MESSAGE_CRC_START, 4);
							uint32_t crc = NETW_MSG::MSG::byteToUInt4((char*)msgin.buffer + NETW_MSG::MESSAGE_CRC_START);

							msgout.make_msg_with_crc_and_flag_buffer(
								msgin.type_msg, dout.buffer.size(), (uint8_t*)dout.buffer.getdata(), digestkey, crc, 1, from_user, to_user);

                            if (DEBUG_INFO)
                                ss << "crypto_encrypt - msg encrypted with header, len " << msgout.buffer_len << std::endl;

                            uint8_t new_flag = msgout.buffer[NETW_MSG::MESSAGE_FLAG_START];
                            if (new_flag == 0)
                            {
                                ss << "ERROR crypto_encrypt - invalid crypto flag (0)" <<std::endl;
                            }

                            // TEST
                            //NETW_MSG::MSG msgout2;
                            //r = crypto_decrypt(1,(char*)msgout.buffer,msgout.buffer_len, msgout2);

							main_global::log(ss.str());
                            return true;
						}
                        else
                        {
                            {
                                ss << "WARNING crypto_encrypt - invalid file "
                                << user_folder + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data<<std::endl;
                            }
                        }
					}
					else
                    {
                        {
                            ss << "WARNING crypto_encrypt - encryptor->encrypt() failed" << std::endl;
                        }
                    }
				}
			}
		}

		main_global::log(ss.str());
		return r;
	}
}
