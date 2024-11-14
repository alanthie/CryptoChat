#pragma once
#ifndef CFGSRV_H_INCLUDED
#define CFGSRV_H_INCLUDED

//#include "../uint_util.hpp"
#include "../include/c_plus_plus_serializer.h"

namespace cryptochat
{
    namespace cfg
    {
        struct cfg_srv
        {
            cfg_srv() {}
            void make_default() 
            {
                _server = "127.0.0.1";
                _port = 14003;
                _number_connection = 16;
            }

            cfg_srv(const std::string& srv, int port, int number_connection)
            {
                _server = srv;
                _port = port;
                _number_connection = number_connection;
            }

            std::string _server;
            int  _port;
            int  _number_connection;
            std::map<std::string, std::string> map_challenges;

            friend std::ostream& operator<<(std::ostream& out, Bits<cfg_srv& > my)
            {
                out << bits(my.t._server) << bits(my.t._port) << bits(my.t._number_connection) << bits(my.t.map_challenges);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<cfg_srv&> my)
            {
                in >> bits(my.t._server) >> bits(my.t._port) >> bits(my.t._number_connection) >> bits(my.t.map_challenges);
                return (in);
            }
        };
    }
}

#endif

