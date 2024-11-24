#pragma once
#ifndef Repository_H_INCLUDED
#define Repository_H_INCLUDED

#include <string>
#include <map>
#include "../include/file_util.hpp"
#include "../include/c_plus_plus_serializer.h"

namespace cryptochat
{
    namespace db
    {
        struct repo_userinfo
        {
            std::string host;
            std::string usr;
            std::string folder;

            friend std::ostream& operator<<(std::ostream& out, Bits<repo_userinfo&>  my)
            {
                out << bits(my.t.host)
                    << bits(my.t.usr)
                    << bits(my.t.folder);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<repo_userinfo&> my)
            {
                in >> bits(my.t.host)
                    >> bits(my.t.usr)
                    >> bits(my.t.folder);
                return (in);
            }
        };

        class repo_info
        {
        public:
            size_t counter = 0;
            std::map<uint32_t, repo_userinfo> map_userinfo;

            friend std::ostream& operator<<(std::ostream& out, Bits<repo_info&>  my)
            {
                out << bits(my.t.counter) << bits(my.t.map_userinfo);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<repo_info&> my)
            {
                in >> bits(my.t.counter) >> bits(my.t.map_userinfo);
                return (in);
            }
        };

        class Repository
        {
        public:
            const std::string REPO_INFO = "repoinfo.dat";
            const std::string USER_INFO = "userinfo.txt";
            const std::string FOLDER_ME = "me"; // client private keys db

            std::string _root_path;
            repo_info   _repo_info;

            Repository() = default;

            std::string folder_me()
            {
                std::string folder = _root_path + "/" + FOLDER_ME;
                return folder;
            }

            static std::string file_separator()
            {
#ifdef _WIN32
                return "\\";
#else
                return "/";
#endif
            }
            std::string get_user_folder(uint32_t user_index)
            {
                return _root_path + file_separator() + "user_" + std::to_string(user_index);
            }

            std::string get_crypto_cfg_filename(uint32_t user_index)
            {
                return get_user_folder(user_index) + file_separator() + "cfg.ini";
            }

            std::string get_urls_folder(uint32_t user_index)
            {
                return get_user_folder(user_index);
            }

            std::string folder_name(uint32_t user_index, const std::string& in_host, const std::string& in_usr)
            {
                return get_user_folder(user_index);
            }

            bool save_repo(std::string& serr)
            {
                if (_root_path.size() == 0)
                {
                    serr += "WARNING save_repo - empty repo root pathname ";
                    return false;
                }

                std::string filename = _root_path + file_separator() + REPO_INFO;
                if (file_util::fileexists(filename) == false)
                {
                    serr += "WARNING save_repo - repo info not found (creating...) " + filename;
                }

                // REPO_INFO
                {
                	std::ofstream out;
					out.open(filename, std::ios_base::out);
					out << bits(_repo_info);
					out.close();
                }

                {
                    std::string filenameinfo = _root_path + file_separator() + USER_INFO;
                    std::ofstream outfile2(filenameinfo);

                    std::stringstream ss;
                    for (auto& c : _repo_info.map_userinfo)
                    {
                        ss << " host: " + c.second.host + " username: " + c.second.usr + "\n";
                    }
                    outfile2 << ss.str();
                    outfile2.close();
                }
                return true;
            }

            bool read_repo(std::string& serr)
            {
                if (_root_path.size() == 0)
                {
                    serr += "WARNING read_repo - empty repo root pathname ";
                    return false;
                }

                std::string filename = _root_path + file_separator() + REPO_INFO;
                if (file_util::fileexists(filename) == false)
                {
                    serr += "WARNING read_repo - repo info not found (no user registered so far) " + filename;
                    return false;
                }

                try
                {
                    std::ifstream infile;
                    infile.open (filename, std::ios_base::in);
                    infile >> bits(_repo_info);
                    infile.close();
                }
                catch (...)
                {
                    serr += "WARNING read_repo - repo info can not be read " + filename;
                    return false;
                }

                return true;;
            }

            bool set_root(const std::string& root_path, std::string& serr)
            {
                bool r = false;
                if (root_path.size() == 0)
                {
                    serr += "ERROR set_root - empty repo root pathname ";
                    return false;
                }

                if (file_util::fileexists(root_path))
                {
                    // check
                    if (std::filesystem::is_directory(root_path))
                    {
                        _root_path = root_path;

                        r = read_repo(serr);
                        if (!r)
                        {
                            // ok may not exist at start
                        }

                        r = add_me(serr);
                        if (!r)
                        {
                            return false;
                        }
                    }
                    else
                    {
                        serr += "ERROR set_root - repo root not a directory " + root_path;
                        r = false;
                    }
                }
                else
                {
                    {
                        r = std::filesystem::create_directories(root_path);
                        if (r)
                        {
                            _root_path = root_path;
                        }
                        else
                        {
                            serr += "ERROR set_root - can not create the repo root directory " + root_path;
                        }
                    }
                }

                return r;
            }

            bool user_exist(uint32_t user_index, const std::string& in_host, const std::string& in_usr)
            {
                if (_root_path.size() == 0) return false;
                std::string folder = folder_name(user_index, in_host, in_usr);
                return file_util::fileexists(folder);
            }

            bool add_me(std::string& serr)
            {
                bool r = true;
                if (_root_path.size() == 0)
                {
                    serr += "WARNING add_me - empty repo root pathname ";
                    return false;
                }

                std::string folder = folder_me();
                if (file_util::fileexists(folder))
                {
                    if (std::filesystem::is_directory(folder))
                        return true;

                    serr += "WARNING add_me - me folder is not a directory " + folder;
                    return false;
                }

                r = std::filesystem::create_directories(folder);
                if (r)
                {
                    if (std::filesystem::is_directory(folder))
                        return true;

                    serr += "WARNING add_me - me folder is not a directory " + folder;
                    return false;
                }
                else
                {
                    serr += "WARNING add_me - Unable to create me folder " + folder;
                }
                return r;
            }

            bool add_user(uint32_t user_index, const std::string& hostname, const std::string& username, std::string& serr)
            {
                bool r = true;
                if (_root_path.size() == 0)
                {
                    serr += "WARNING add_user - empty repo root pathname ";
                    return false;
                }

                if (_repo_info.map_userinfo.contains(user_index))
                {
                    bool changed = false;
                    if (hostname.size() > 0 && _repo_info.map_userinfo[user_index].host.size() == 0)
                    {
                        _repo_info.map_userinfo[user_index].host = hostname;
                        changed = true;
                    }
                    if (username.size() > 0 && _repo_info.map_userinfo[user_index].usr.size() == 0)
                    {
                        _repo_info.map_userinfo[user_index].usr = username;
                        changed = true;
                    }

                    if (changed)
                    {
                       r = save_repo(serr);
                       if (!r)
                       {
                           return false;
                       }
                    }
                }

                std::string folder = folder_name(user_index, hostname, username);
                if (file_util::fileexists(folder))
                {
                    if (std::filesystem::is_directory(folder))
                        return true;

                    serr += "WARNING add_user - user folder is not a directory " + folder;
                    return false;
                }

                r = std::filesystem::create_directories(folder);
                if (r)
                {
                    repo_userinfo ur;
                    ur.host = hostname;
                    ur.usr = username;
                    ur.folder = folder;

                    _repo_info.map_userinfo[user_index] = ur;
                    _repo_info.counter++;

                    r = save_repo(serr);
                    if (r)
                    {
                        std::string filenamecfg = folder + file_separator()  + "cfg.ini";
                        r = make_default_crypto_cfg(filenamecfg, folder + file_separator());
                        if (!r)
                        {
                            serr += "WARNING add_user - Unable to create file " + filenamecfg + " in folder " + folder;
                        }
                        else
                        {
                            std::string filenameurls = folder + file_separator() + "urls.txt";
                            r = make_default_urls(filenameurls, folder + file_separator());
                            if (!r)
                            {
                                serr += "WARNING add_user - Unable to create file " + filenameurls + " in folder " + folder;
                            }
                        }
                    }
                }
                else
                {
                    serr += "WARNING add_user - Unable to create user folder " + folder;
                }
                return r;

            }

            bool make_default_crypto_cfg(const std::string& filename, const std::string& folder_cfg)
            {
                std::stringstream ss;

                ss << ";\n";
                ss << ";cfg.ini\n";
                ss << ";\n";
                ss << ";\n";
                ss << "[cmdparam]"; ss << "\n";
                ss << "filename_urls = urls.txt"; ss << "\n";
                ss << "filename_msg_data = msg.zip"; ss << "\n";
                ss << "filename_puzzle ="; ss << "\n";
                ss << "filename_full_puzzle ="; ss << "\n";
                ss << "filename_encrypted_data = msg.zip.encrypted"; ss << "\n";
                ss << "filename_decrypted_data ="; ss << "\n";
                ss << "keeping = 0"; ss << "\n";
                ss << "folder_local = "             + folder_cfg + "other/local/"; ss << "\n";
                ss << "folder_my_private_rsa = "    + folder_cfg + "me/"; ss << "\n";
                ss << "folder_other_public_rsa = "  + folder_cfg + "other/"; ss << "\n";
                ss << "folder_my_private_ecc = "    + folder_cfg + "me/"; ss << "\n";
                ss << "folder_other_public_ecc = "  + folder_cfg + "other/"; ss << "\n";
                ss << "folder_my_private_hh = "     + folder_cfg + "me/"; ss << "\n";
                ss << "folder_other_public_hh = "   + folder_cfg + "other/"; ss << "\n";
                ss << "wbaes_my_private_path = "    + folder_cfg + ""; ss << "\n";
                ss << "wbaes_other_public_path = "  + folder_cfg + ""; ss << "\n";
                ss << "encryped_ftp_user ="; ss << "\n";
                ss << "encryped_ftp_pwd ="; ss << "\n";
                ss << "known_ftp_server ="; ss << "\n";
                ss << "auto_flag ="; ss << "\n";
                ss << "use_gmp = 1"; ss << "\n";
                ss << "self_test = 0"; ss << "\n";
                ss << "key_size_factor = 3"; ss << "\n";
                ss << "shufflePerc = 0"; ss << "\n";
                ss << "converter ="; ss << "\n";
                ss << "check_converter ="; ss << "\n";
                ss << "verbose = 1"; ss << "\n";
                ss << ""; ss << "\n";
                ss << "[keymgr]"; ss << "\n";
                ss << "max_usage1 = keytype:rsa, bits : 64, max_usage_count : 1"; ss << "\n";
                ss << "max_usage2 = keytype : rsa, bits : 1024, max_usage_count : 16"; ss << "\n";
                ss << ""; ss << "\n";
                ss << "[keygen]"; ss << "\n";
                ss << "policy1 = keytype : rsa, pool_first : 10, pool_random : 30, pool_last : 10, pool_new : 20, pool_max : 100"; ss << "\n";
                ss << ""; ss << "\n";
                ss << "[algo]"; ss << "\n";
                ss << "ALGO_BIN_AES_128_ecb = 0"; ss << "\n";
                ss << "ALGO_BIN_AES_128_cbc = 0"; ss << "\n";
                ss << "ALGO_BIN_AES_128_cfb = 1"; ss << "\n";
                ss << "ALGO_BIN_AES_256_ecb = 1"; ss << "\n";
                ss << "ALGO_BIN_AES_256_cbc = 1"; ss << "\n";
                ss << "ALGO_BIN_AES_256_cfb = 1"; ss << "\n";
                ss << "ALGO_TWOFISH = 1"; ss << "\n";
                ss << "ALGO_Salsa20 = 1"; ss << "\n";
                ss << "ALGO_IDEA = 1"; ss << "\n";
                ss << "ALGO_wbaes512 = 1"; ss << "\n";
                ss << "ALGO_wbaes1024 = 1"; ss << "\n";
                ss << "ALGO_wbaes2048 = 1"; ss << "\n";
                ss << "ALGO_wbaes4096 = 1"; ss << "\n";
                ss << "ALGO_wbaes8192 = 1"; ss << "\n";
                ss << "ALGO_wbaes16384 = 1"; ss << "\n";
                ss << "ALGO_wbaes32768 = 1"; ss << "\n";

                std::ofstream outfile(filename);
                outfile << ss.str();
                outfile.close();
                return true;
            }

            bool make_default_urls(const std::string& filename, const std::string& folder_url)
            {
                std::stringstream ss;

                ss << ";\n";
                ss << ";------------------------------------------------------------------------\n";
                ss << "; URL keys source when encoding :\n";
                ss << ";------------------------------------------------------------------------\n";
                ss << "[r:]last=1,first=1,random=5;\n";
                ss << ";\n";
                ss << ";------------------------------------------------------------------------\n";
                ss << "; GLOBAL parameters\n";
                ss << ";------------------------------------------------------------------------\n";
                ss << ";Repeat all keys generation N times producing more encoding rounds\n";
                ss << "[repeat]1\n";
                ss << ";\n";
                ss << ";\n";

                std::ofstream outfile(filename);
                outfile << ss.str();
                outfile.close();
                return true;
            }

        };
    }
}

#endif
