#pragma once
#ifndef CFGCLI_H_INCLUDED
#define CFGCLI_H_INCLUDED

//#include "../uint_util.hpp"
#include <string>
#include <map>
#include "../include/c_plus_plus_serializer.h"
#include "../include/file_util.hpp"

namespace cryptochat
{
    namespace cfg
    {
        struct cfg_cli
        {
            cfg_cli() {}

            void make_default()
            {
                _server = "127.0.0.1";
                _port = 14003;
                _username = NETW_MSG::DEFAULT_USERNAME;
				_repo_root_path = "./cryptochat"; // should have a non relative path TODO...- not using default
            }

            cfg_cli(const std::string& srv, int port, int number_connection, const std::string& user, const std::string& repo_root_path)
            {
                _server = srv;
                _port = port;
                _username = user;
				_repo_root_path = repo_root_path;
            }

            bool read_cfg(const std::string& filename, bool create_if_not_exist, std::string& serr)
			{
				bool ret = false;
				bool has_cfg_file = false;

				if (filename.size() == 0)
				{
					serr += "WARNING read_cfg - cfg filename empty";
				}
				else if (file_util::fileexists(filename) == false)
				{
					serr += "WARNING read_cfg - cfg file not found: " + filename;
					if (create_if_not_exist)
					{
						make_default();
						std::ofstream outfile(filename, std::ios_base::out);
						outfile << bits(*this);
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
						std::ifstream in(filename, std::ios_base::in);
						in >> bits(*this);
						in.close();
						ret = true;
					}
					catch (const std::exception& e)
					{
						serr += "WARNING read_cfg - unable to read file " + filename + "\n";
						serr += "Exception thrown: " + std::string(e.what()) + "\n";
					}
					catch (...)
					{
						serr += "WARNING read_cfg - unable to read file " + filename + "\n";
						serr += "Exception thrown\n";
					}
				}
				return ret;
			}

            bool save_cfg(const std::string& filename, std::string& serr)
			{
				if (filename.size() == 0)
				{
					serr += "WARNING save_cfg - cfg file name empty: ";
					return false;
				}

				try
				{
					std::ofstream outfile(filename, std::ios_base::out);
					outfile << bits(*this);
					outfile.close();
					return true;
				}
				catch (const std::exception& e)
				{
					serr += "WARNING save_cfg - unable to save file " + filename + "\n";
					serr += "Exception thrown: " + std::string(e.what()) + "\n";
				}
				catch (...)
				{
					serr += "WARNING save_cfg - unable to save file " + filename + "\n";
					serr += "Exception thrown\n";
				}
				return false;
			}

            std::string _server;
            int			_port;
            std::string _username;
			std::string _repo_root_path;
            std::map<std::string, std::string> map_challenges;

            friend std::ostream& operator<<(std::ostream& out, Bits<cfg_cli& > my)
            {
                out << bits(my.t._server) << bits(my.t._port) << bits(my.t._username)
					<< bits(my.t._repo_root_path)
					<< bits(my.t.map_challenges);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<cfg_cli&> my)
            {
                in  >> bits(my.t._server) >> bits(my.t._port) >> bits(my.t._username)
					>> bits(my.t._repo_root_path)
					>> bits(my.t.map_challenges);
                return (in);
            }
        };
    }
}

#endif


