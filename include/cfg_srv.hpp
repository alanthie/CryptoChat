#pragma once
#ifndef CFGSRV_H_INCLUDED
#define CFGSRV_H_INCLUDED

#include "../include/c_plus_plus_serializer.h"
#include "../include/vigenere.hpp"
#include "../include/string_util.hpp"
#include "../include/challenge.hpp"
//

namespace cryptochat
{
    namespace cfg
    {
        struct cfg_srv
        {
            cfg_srv() : _server(""), _port(14003), _number_connection(16)
            {
                make_default();
            }

            void make_default()
            {
                _server = "127.0.0.1";
                _port = 14003;
                _number_connection = 16;
                _map_challenges["TFirst prime number\nT1000th prime number"] = "27919";
                _machineid_filename = std::filesystem::current_path().string() + "/" + "machineid.dat";
            }

            cfg_srv(const std::string& srv, int port, int number_connection)
            {
                _server = srv;
                _port = port;
                _number_connection = number_connection;
                _map_challenges["TFirst prime number;TFirst prime number;T1000th prime number"] = "227919";
                _machineid_filename = std::filesystem::current_path().string() + "/" + "machineid.dat";
            }

            void print()
            {
                int cnt=0;
                std::cout << "Port : " << _port << std::endl;
                std::cout << "Number of connection allowed : " << _number_connection << std::endl;
                std::cout << "Machineid list filename : " << _machineid_filename << std::endl;
                std::cout << "_extra_challenge_file : " << _extra_challenge_file << std::endl;

                {
                    std::map<std::string, std::string> map_out;
                    std::string out_error;
                    bool r = NETW_MSG::challenge_read_from_file(_extra_challenge_file, map_out, out_error);
                    if (r)
                    {
                        for (auto& e : map_out)
                        {
                            _map_challenges[std::string(e.first)] = e.second;
                        }
                        std::cout << std::endl;
                    }
                }

                std::cout << "Number of challenges: " << _map_challenges.size() << std::endl;
                for (auto& ch : _map_challenges)
                {
                    std::string key = ch.first;
                    std::cout << "challenge " << cnt << ":" << std::endl;
                    print_challenge(key, ch.second);
                    cnt++;
                }
                std::cout << std::endl;

            }

            void print_challenge(std::string key, const std::string& answer)
            {
                {
                    std::vector<std::string> lines = NETW_MSG::split(key, "\n");
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
                    for (size_t i = 0; i < comments.size(); i++)
                    {
                        std::cout << comments[i] << std::endl;
                    }
                    for (size_t i = 0; i < questions.size(); i++)
                    {
                        std::cout << questions[i] << std::endl;
                    }
                    std::cout << "Answer= " << answer << std::endl;
                    std::cout << std::endl;
                }
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
                std::cout << std::endl;

                std::cout << "Machineid list filename (Default: " << cfg_default._machineid_filename << ") : ";
                _machineid_filename = cfg_default._machineid_filename;
                std::getline(std::cin, entry); 
                if (!entry.empty())
                {
                    // Validate file ........... TODO
                    _machineid_filename = entry;
                }
                std::cout << std::endl;

                int yes_no  = 0 ;
                // cryptoAL_vigenere::AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
                std::cout << "Number of default challenges: " << cfg_default._map_challenges.size() << std::endl;
                int cnt=0;
                for (auto& ch : cfg_default._map_challenges)
                {
                    std::string key = ch.first;
                    std::cout << "challenge " << cnt << ":" << std::endl;
                    print_challenge(key, ch.second);

                    std::cout << "Accept challenge (0/1): ";
                    std::getline(std::cin, entry); if (!entry.empty()) yes_no = (int)NETW_MSG::str_to_ll(entry);
                    if (yes_no == 1)
                    {
                        _map_challenges[ch.first] = ch.second;
                    }
                    cnt++;
                }

                std::cout << "Extra file of challenges (Default: " << cfg_default._extra_challenge_file << ") : ";
                std::getline(std::cin, entry); 
                if (!entry.empty())
                {
                    if (file_util::fileexists(entry))
                    {
                        _extra_challenge_file = entry;
                    }
                    else
                    {
                        std::cout << "ERROR - No file" << std::endl;
                    }
                }
            }

            std::string _server;
            int  _port;
            int  _number_connection;
            std::map<std::string, std::string> _map_challenges;
            std::string _extra_challenge_file;
            std::string _machineid_filename;

            friend std::ostream& operator<<(std::ostream& out, Bits<cfg_srv& > my)
            {
                out << bits(my.t._server) << bits(my.t._port) << bits(my.t._number_connection) << bits(my.t._map_challenges) << bits(my.t._extra_challenge_file);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<cfg_srv&> my)
            {
                in >> bits(my.t._server) >> bits(my.t._port) >> bits(my.t._number_connection) >> bits(my.t._map_challenges) >> bits(my.t._extra_challenge_file);
                return (in);
            }
        };
    }
}

#endif

