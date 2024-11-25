#pragma once
#ifndef CHATCLI_H_INCLUDED
#define CHATCLI_H_INCLUDED

/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <limits>
#include <csignal>
#include <chrono>
#include "../include/crypto_client.hpp"
#include "../include/cfg_cli.hpp"
#include "../include/string_util.hpp"
#include "../include/argparse.hpp"
#include "../include/crypto_parsing.hpp"

namespace cryptochat
{
	namespace cli
	{
		class chat_cli
		{
		public:
			chat_cli(const std::string& cfgfile) : _cfg_file(cfgfile)
			{
			}

			~chat_cli()
			{
				if (_chat_cli != nullptr)
				{
                    std::cout << "deleting chat_cli" << std::endl;
					delete _chat_cli;
					_chat_cli = nullptr;
                }
			}


			bool read_cfg(bool create_if_not_exist, std::string& serr)
			{
                return _cfg.read_cfg(_cfg_file, create_if_not_exist, serr);
			}

			bool save_cfg(std::string& serr)
			{
                return _cfg.save_cfg(_cfg_file, serr);
			}

			int run(std::string& serr)
			{
				got_chat_cli_signal = 0;

				bool ok = read_cfg(false, serr);
				if (ok)
				{
					std::cout << "Server : " << _cfg._server << std::endl;
					std::cout << "Port : " << _cfg._port << std::endl;
					std::cout << "Username : " << _cfg._username << std::endl;
					std::cout << "Repository : " << _cfg._repo_root_path << std::endl;
				}
				else
				{
					std::string entry;

					_cfg._server = "127.0.0.1";
					std::cout << "Server (Default 127.0.0.1): ";
					std::getline(std::cin, entry); if (!entry.empty()) _cfg._server = entry;

					_cfg._port = 14003;
					std::cout << "Port (Default 14003): ";
					std::getline(std::cin, entry); if (!entry.empty()) _cfg._port = (int)NETW_MSG::str_to_ll(entry);

					_cfg._username = "user";
					std::cout << "Username (Default user): ";
					std::getline(std::cin, entry); if (!entry.empty()) _cfg._username = entry;

					// TODO...
#ifdef _WIN32
					_cfg._repo_root_path = "C:\\cpp\\test\\cryptochat";
#else
					_cfg._repo_root_path = "/home/allaptop/dev/test/cryptochat";
#endif
					std::cout << "Repository (Default " + _cfg._repo_root_path + "): ";
					std::getline(std::cin, entry); if (!entry.empty()) _cfg._repo_root_path = entry;
					// validate...

					std::cout << "Server : " << _cfg._server << std::endl;
					std::cout << "Port : " << _cfg._port << std::endl;
					std::cout << "Username : " << _cfg._username << std::endl;
					std::cout << "Repository : " << _cfg._repo_root_path << std::endl;

					bool r = save_cfg(serr);
				}

				try {
					_chat_cli = new crypto_socket::crypto_client(_cfg, _cfg_file);
					_chat_cli->setOnMessage([](const std::string& t_message) {std::cout << t_message << std::endl; });
					_chat_cli->connectServer();
					_chat_cli->client_UI();

					// The destructor of crypto_socket::crypto_client call closeConnection that join with the client threads

				}
				catch (const std::exception& e) 
				{
					std::cerr << "Exception thrown: " << e.what() << std::endl;
				}
				catch(...)
				{
					std::cerr << "Exception thrown" << std::endl;
				}

				// EXITING
				std::this_thread::sleep_for(std::chrono::seconds(1));
				return 0;
			}

			std::string					_cfg_file;
			cryptochat::cfg::cfg_cli	_cfg;
			crypto_socket::crypto_client*         _chat_cli = nullptr;

			static std::atomic<int> got_chat_cli_signal;
		};

	}
}

#endif
