#pragma once
#ifndef CFGCLI_H_INCLUDED
#define CFGCLI_H_INCLUDED

//#include "../uint_util.hpp"
#include <string>
#include <map>
#include "../include/c_plus_plus_serializer.h"

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
                _username  = "user";
            }

            cfg_cli(const std::string& srv, int port, int number_connection, const std::string& user)
            {
                _server = srv;
                _port = port;
                _username = user;

            }

            std::string _server;
            int  _port;
            std::string _username;
            std::map<std::string, std::string> map_challenges;

            friend std::ostream& operator<<(std::ostream& out, Bits<cfg_cli& > my)
            {
                out << bits(my.t._server) << bits(my.t._port) << bits(my.t._username) << bits(my.t.map_challenges);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<cfg_cli&> my)
            {
                in >> bits(my.t._server) >> bits(my.t._port) >> bits(my.t._username) >> bits(my.t.map_challenges);
                return (in);
            }
        };
    }
}

#endif


