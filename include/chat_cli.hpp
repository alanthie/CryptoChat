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
#include "../include/ysClient.h"
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

			bool read_cfg(bool create_if_not_exist)
			{
				bool ret = false;
				bool has_cfg_file = false;

				if (_cfg_file.size() == 0)
				{
				}
				else if (file_util::fileexists(_cfg_file) == false)
				{
					std::cerr << "WARNING cfg file not found " << _cfg_file << std::endl;
					if (create_if_not_exist)
					{
						_cfg.make_default();
						std::ofstream outfile(_cfg_file, std::ios::binary);
						outfile << bits(_cfg);
						has_cfg_file = true;
					}
				}
				else
				{
					has_cfg_file = true;
				}

				if (has_cfg_file)
				{
					// READ _cfg
					try
					{
						std::ifstream in(_cfg_file);
						in >> bits(_cfg);
						ret = true;
					}
					catch (...)
					{
						ret = false;
					}
				}
				return ret;
			}

			bool save_cfg()
			{
				bool ret = false;
				bool has_cfg_file = false;

				if (_cfg_file.size() == 0)
				{
					return false;
				}

				try
				{
					std::ofstream outfile(_cfg_file, std::ios::binary);
					outfile << bits(_cfg);
					return true;
				}
				catch (...)
				{
				}
				return false;

			}

			int run()
			{
				signal(SIGINT, signalHandler);

				bool ok = read_cfg(true);
				if (ok)
				{
					std::cout << "Server : " << _cfg._server << std::endl;
					std::cout << "Port : " << _cfg._port << std::endl;
					std::cout << "Username : " << _cfg._username << std::endl;
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

					std::cout << "Server : " << _cfg._server << std::endl;
					std::cout << "Port : " << _cfg._port << std::endl;
					std::cout << "Username : " << _cfg._username << std::endl;

					bool r = save_cfg();
				}

				try {

					_chat_cli = new ysSocket::ysClient(_cfg._server, _cfg._port);
					_chat_cli->setOnMessage([](const std::string& t_message) {std::cout << t_message << std::endl; });
					_chat_cli->connectServer();
					_chat_cli->client_UI();
					delete _chat_cli;

				}
				catch (const std::exception& e) {
					std::cerr << e.what() << std::endl;
				}

				std::this_thread::sleep_for(std::chrono::seconds(5));
				return 0;
			}

			std::string					_cfg_file;
			cryptochat::cfg::cfg_cli	_cfg;
			ysSocket::ysClient* _chat_cli = nullptr;

			static void signalHandler(int code)
			{
				char ch;
				std::cout << "Are you sure you want to close socket?(Y/N)";
				std::cin >> ch;
				if (toupper(ch) == 'Y') {
					//if (global_cli != nullptr)
					//	delete global_cli;
					exit(0);
				}
				std::cin.clear();
				//cin.ignore(numeric_limits<streamsize>::max(), '\n');
				std::cin.ignore(0x7fffffffffffffff, '\n');
			}
		};

	}
}

#endif