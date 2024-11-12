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

#include <ciso646>
#include <iostream>
#include <string>

extern int mainMenu(ysSocket::ysClient* netw_client);

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
			std::cout << "WSAGetLastError() = " << r;
#endif
			throw std::runtime_error("could not connect to server");
		}
	}

	void ysClient::receiveMessage()
	{
		this->m_thread = std::move(std::thread([=, this]
		{
			int len;
			char message_buffer[MESSAGE_SIZE + 1] = { 0 };

			while ((len = recv(this->m_socketFd, message_buffer, MESSAGE_SIZE, 0)) > 0)
			{
				message_buffer[len] = '\0';

				// Parse message
				NETW_MSG::MSG m;
				bool r;
				if (!key_valid)
					r = m.parse(message_buffer, len, getDEFAULT_KEY());
				else if (!rnd_valid)
					r = m.parse(message_buffer, len, initial_key);
				else
					r = m.parse(message_buffer, len, random_key);

                if (r == true)
                {
                    std::string str_message = m.get_data_as_string();

                    if (m.type_msg == NETW_MSG::MSG_CMD_REQU_KEY_HINT)
                    {
                        challenge_attempt++;
                        std::vector<std::string> questions = split(str_message, ";");

						std::vector< std::string> a;
						for (size_t i = 0; i < questions.size(); i++) a.push_back({});

                        while (true)
                        {
                            Menu qa;
                            qa.set_heading(std::string("Challenges (q TO QUIT MENU)")
                            + std::string(" [Attempt: ") + std::to_string(challenge_attempt) + "]");

                            qa.set_max_len(80);
                            for(size_t i = 0; i< questions.size(); i++)
                                qa.add_field( std::string("[" + std::to_string(i+1) + "] ") + questions[i] + " : " + a[i], nullptr);

                            int c = qa.get_menu_choice();
                            if (c == 'q')
                            {
                                break;
                            }

                            int idx = c - '1';
                            if ((idx >= 0) && (idx < questions.size()))
                            {
                                a[idx] = get_input("Enter answer [" + std::to_string(idx+1) + "]");
                            }

                        }

                        std::string r;
                        for(size_t i = 0; i< questions.size(); i++)
                        {
                            r += a[i];
                            //if (i <  questions.size() - 1) r+=";";
                        }



                        // ask user
                        {
                            if (DEBUG_INFO) std::cout << "recv MSG_CMD_REQU_KEY_HINT" << std::endl;

//                            showMessage(str_message);
//                            std::string r = get_input("Enter key");
                            initial_key = r; // still key_valid = false;

                            if (DEBUG_INFO) std::cout << "send MSG_CMD_RESP_KEY_HINT" << std::endl;
							NETW_MSG::MSG m;
                            m.make_msg(NETW_MSG::MSG_CMD_RESP_KEY_HINT, r, getDEFAULT_KEY());
                            this->sendMessageBuffer(this->m_socketFd, m, getDEFAULT_KEY());
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_VALID)
                    {
                        {
                            if (DEBUG_INFO) std::cout << "recv MSG_CMD_INFO_KEY_VALID" << std::endl;

                            // CONFIRMED new key
                            key_valid = true;

                            showMessage(str_message);
                            add_to_history(true, NETW_MSG::MSG_CMD_INFO_KEY_VALID, str_message);
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_INVALID)
                    {
                        {
                            if (DEBUG_INFO) std::cout << "recv MSG_CMD_INFO_KEY_INVALID" << std::endl;

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

                        if (DEBUG_INFO) std::cout << "recv MSG_CMD_REQU_ACCEPT_RND_KEY" << std::endl;
                        if (DEBUG_INFO)
                        {
                            std::cout << "Random key recv ["
                                + get_summary_hex((char*)work.data(), work.size())
                                + "]" << std::endl;

                            std::cout << "Random key digest recv ["
                                + str_digest
                                + "]" << std::endl;

                            CRC32 chk;
                            chk.update((char*)work.data(), work.size());
                            std::cout << "Random key CRC32 recv ["
                            << chk.get_hash()
                            << "]" << std::endl;
                        }


                        if (DEBUG_INFO) std::cout << "send MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
						NETW_MSG::MSG m;
                        m.make_msg(NETW_MSG::MSG_CMD_RESP_ACCEPT_RND_KEY, str_digest, rnd_valid ? random_key : initial_key);
                        this->sendMessageBuffer(this->m_socketFd, m, rnd_valid ? random_key : initial_key);
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_RND_KEY_VALID)
                    {
                        {
                            if (DEBUG_INFO) std::cout << "recv MSG_CMD_INFO_RND_KEY_VALID" << std::endl;

                            // CONFIRMED new rnd key
                            random_key = pending_random_key;
                            rnd_valid = true;
                        }
                    }
                    else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_USERNAME)
                    {
                        {
                            if (DEBUG_INFO) std::cout << "recv MSG_CMD_REQU_USERNAME" << std::endl;

                            showMessage(str_message);
                            std::string r = get_input("Enter username");

                            if (r.size() == 0) r = "anonymous";
                            user_valid = true;

                            if (DEBUG_INFO) std::cout << "send MSG_CMD_RESP_USERNAME" << std::endl;
							NETW_MSG::MSG m;
                            m.make_msg(NETW_MSG::MSG_CMD_RESP_USERNAME, r, rnd_valid ? random_key : initial_key);
                            this->sendMessageBuffer(this->m_socketFd, m, rnd_valid ? random_key : initial_key);
                        }
                    }

                    else if (m.type_msg == NETW_MSG::MSG_TEXT)
                    {
                        if (DEBUG_INFO) std::cout << "recv MSG_TEXT : " << m.get_data_as_string() << std::endl;

                        showMessage(str_message);
                        add_to_history(true, NETW_MSG::MSG_TEXT, str_message);
                    }
                }

				std::memset(message_buffer, '\0', sizeof (message_buffer));
			}
			this->m_state = STATE::CLOSED;
		}));
	}

	void ysClient::writeMessage()
	{
		int cnt = 0;
		std::string message = "";

		while (this->m_state == STATE::OPEN)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));

			if (cnt == 0)
			{
				//message = get_input("Send first msg to server to receive instructions");

				if (DEBUG_INFO) std::cout << "send MSG_TEXT" << std::endl;
				if (message.size() == 0) message = "hello";

				NETW_MSG::MSG m;
				m.make_msg(NETW_MSG::MSG_TEXT, message, getDEFAULT_KEY());
				this->sendMessageBuffer(this->m_socketFd, m, getDEFAULT_KEY());

				std::string s = m.get_data_as_string();
				add_to_history(false, NETW_MSG::MSG_TEXT, s);

				cnt++;
			}

			if (key_valid && rnd_valid && user_valid)
			{
				mainMenu(this);
			}
			else if (!user_valid)
			{

			}
			else if (key_valid || rnd_valid)
			{
				{
					message = get_input("Enter chat msg");

					std::string key;
					if (!key_valid)
						key = getDEFAULT_KEY();
					else if (!rnd_valid)
						key = initial_key;
					else
						key = random_key;

					NETW_MSG::MSG m;
					m.make_msg(NETW_MSG::MSG_TEXT, message, key);
					if (DEBUG_INFO) std::cout << "send MSG_TEXT" << std::endl;

					this->sendMessageBuffer(this->m_socketFd, m, key);

					std::string s = m.get_data_as_string();
					add_to_history(false, NETW_MSG::MSG_TEXT, s);

					cnt++;
				}
			}
		}
	}

	ysClient::ysClient() :
	ysNodeV4() {
		setDefault();
	}

	ysClient::ysClient(const int& t_port) :
	ysNodeV4(t_port) {
		setDefault();
	}

	ysClient::ysClient(const std::string& t_serverName, const int& t_port) :
	ysNodeV4(t_port), m_serverName(t_serverName) {
		setDefault();
	}

	void ysClient::setOnMessage(const std::function<void(const std::string&)>& t_function) {
		m_onMessage = t_function;
	}

	void ysClient::connectServer() {
		this->_connectServer();
		showMessage("Connection successfully....");
		this->receiveMessage();
		this->writeMessage();
	}

	void ysClient::closeConnection() {
		this->closeSocket();
		if (this->m_thread.joinable()) {
			this->m_thread.join();
		}
	}

	ysClient::~ysClient() {
		this->closeConnection();
	}

}
