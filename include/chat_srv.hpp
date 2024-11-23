#pragma once
#ifndef CHATSRV_H_INCLUDED
#define CHATSRV_H_INCLUDED

/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <limits>
#include <csignal>
#include <chrono>
#include "../include/ysServer.h"
#include "../include/cfg_srv.hpp"
#include "../include/string_util.hpp"
#include "../include/argparse.hpp"
#include "../include/crypto_parsing.hpp"

namespace cryptochat
{
	namespace srv
	{
		class chat_srv
		{
		public:
			chat_srv(const std::string& cfgfile) : _cfg_file(cfgfile)
			{
			}
			~chat_srv()
			{
				std::cout << "INFO - deleting chat_srv" << std::endl;
				if (_chat_server != nullptr)
				{
					delete _chat_server;
					_chat_server = nullptr;
				}
			}

			bool read_cfg(bool create_if_not_exist)
			{
				bool ret = false;
				bool has_cfg_file = false;

				if (_cfg_file.size() == 0)
				{
					std::cerr << "WARNING read_cfg - cfg file name empty " << std::endl;
				}
				else if (file_util::fileexists(_cfg_file) == false)
				{
					std::cerr << "WARNING read_cfg - cfg file not found " << _cfg_file << std::endl;
					if (create_if_not_exist)
					{
						_cfg.make_default();
						std::ofstream outfile(_cfg_file, std::ios_base::out);
						outfile << bits(_cfg);
						outfile.close();
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
						std::ifstream in(_cfg_file, std::ios_base::in);
						in >> bits(_cfg);
						in.close();
						ret = true;
					}
					catch (const std::exception& e)
					{
						std::cerr << "WARNING read_cfg() - Exception thrown: " << e.what() << std::endl;
					}
					catch (...)
					{
						std::cerr << "WARNING read_cfg - Exception thrown " << std::endl;
						ret = false;
					}
				}
				return ret;
			}

			bool save_cfg()
			{
				if (_cfg_file.size() == 0)
				{
					std::cerr << "WARNING save_cfg - cfg file name empty " << std::endl;
					return false;
				}

				try
				{
					std::ofstream outfile(_cfg_file, std::ios_base::out);
					outfile << bits(_cfg);
					outfile.close();
					return true;
				}
				catch (const std::exception& e)
				{
					std::cerr << "WARNING save_cfg() - Exception thrown: " << e.what() << std::endl;
				}
				catch (...)
				{
					std::cerr << "WARNING save_cfg - Exception thrown " << std::endl;
				}
				return false;

			}

			int run()
			{
				bool ok = read_cfg(false);
				if (ok)
				{
					_cfg.print();
				}
				else
				{
					_cfg.read();
					_cfg.print();

					bool r = save_cfg();
					if (r == false)
					{
						std::cerr << "WARNING run() - Unable to save config" << std::endl;
					}
				}

				try
				{
					_chat_server = new ysSocket::ysServer(_cfg);
					_chat_server->setOnMessage([](const std::string& t_message) {std::cout << t_message << std::endl; });
					_chat_server->runServer();
				}
				catch (const std::exception& e)
				{
					std::cerr << "WARNING run() - Exception thrown: " << e.what() << std::endl;
				}
				catch (...)
				{
					std::cerr << "WARNING run() - Exception " << std::endl;
				}

				std::this_thread::sleep_for(std::chrono::seconds(5));
				return 0;
			}

			std::string _cfg_file;
			cryptochat::cfg::cfg_srv _cfg;
			ysSocket::ysServer* _chat_server = nullptr;

		};

	}
}

#endif
