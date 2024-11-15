#pragma once
#ifndef CFGSRV_H_INCLUDED
#define CFGSRV_H_INCLUDED

//#include "../uint_util.hpp"
#include "../include/c_plus_plus_serializer.h"
#include "../include/vigenere.hpp"

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
                _map_challenges["Enter abcdef"] = "abcdef";
                _map_challenges["First prime number;First prime number;1000th prime number"] = "227919";
            }

            cfg_srv(const std::string& srv, int port, int number_connection)
            {
                _server = srv;
                _port = port;
                _number_connection = number_connection;
            }

            void print()
            {
                std::cout << "Port : " << _port << std::endl;
                std::cout << "Number of connection allowed : " << _number_connection << std::endl;
                std::cout << "Number of challenges: " << _map_challenges.size() << std::endl;
                for (auto& ch : _map_challenges)
                {
                    std::cout << "Question=" << "[" << ch.first << "]" << " Answer="  << "[" << ch.second << "]" << std::endl;
                }
                std::cout << std::endl;
            }

            void read()
            {
                cfg_srv cfg_default;
                cfg_default.make_default();

                std::string entry;
                _port = cfg_default._port;
                std::cout << "Port (Default: " << cfg_default._port << ") : ";
                std::getline(std::cin, entry); if (!entry.empty()) _port = (int)NETW_MSG::str_to_ll(entry);

                std::cout << "Number of connection allowed (Default: " << cfg_default._number_connection << ") : ";
                _number_connection = cfg_default._number_connection;
                std::getline(std::cin, entry); if (!entry.empty()) _number_connection = (int)NETW_MSG::str_to_ll(entry);

                // cryptoAL_vigenere::AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
                std::cout << "Number of challenges: " << _map_challenges.size() << std::endl;
                for (auto& ch : _map_challenges)
                {
                    std::cout << "Question= " << ch.first << " Answer= " << ch.second << std::endl;
                }

                int yes_no  = 0 ;
                while (true)
                {
                    std::cout << "New challenge (0/1): ";
                    std::getline(std::cin, entry); if (!entry.empty()) yes_no = (int)NETW_MSG::str_to_ll(entry);
                    if (yes_no == 1)
                    {
                        std::string q;
                        std::string a;
                        std::cout << "Question: ";
                        std::getline(std::cin, entry);
                        if (!entry.empty())
                        {
                            q = entry;
                            std::cout << "Answer: ";
                            std::getline(std::cin, entry);
                            if (!entry.empty())
                            {
                                a = entry;
                                if (cryptoAL_vigenere::is_string_ok(a) == true)
                                {
                                    // cryptoAL_vigenere::AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
                                    _map_challenges[q] = a;
                                }
                                else
                                {
                                    std::cout << "Invalid char in answer, use " << cryptoAL_vigenere::AVAILABLE_CHARS << std::endl;
                                }
                            }
                        }
                        yes_no = 0;
                    }
                    else
                    {
                        break;
                    }
                }

            }

            std::string _server;
            int  _port;
            int  _number_connection;
            std::map<std::string, std::string> _map_challenges;

            friend std::ostream& operator<<(std::ostream& out, Bits<cfg_srv& > my)
            {
                out << bits(my.t._server) << bits(my.t._port) << bits(my.t._number_connection) << bits(my.t._map_challenges);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<cfg_srv&> my)
            {
                in >> bits(my.t._server) >> bits(my.t._port) >> bits(my.t._number_connection) >> bits(my.t._map_challenges);
                return (in);
            }
        };
    }
}

#endif

