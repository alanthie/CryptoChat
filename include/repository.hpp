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
            size_t folder_index;

            friend std::ostream& operator<<(std::ostream& out, Bits<repo_userinfo&>  my)
            {
                out
                << bits(my.t.host)
                << bits(my.t.usr)
                << bits(my.t.folder)
                << bits(my.t.folder_index);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<repo_userinfo&> my)
            {
                in
                >> bits(my.t.host)
                >> bits(my.t.usr)
                >> bits(my.t.folder)
                >> bits(my.t.folder_index);
                return (in);
            }
        };

        class repo_info
        {
        public:
            size_t counter = 0;
            std::map<std::string, repo_userinfo> map_userinfo;

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
            std::string _root_path;

            repo_info _repo_info;

            Repository() = default;

            std::string folder_name(const std::string& machineid, const std::string& in_host, const std::string& in_usr)
            {
                std::string folder;
//                if (_repo_info.map_userinfo.contains(machineid))
//                    folder = _root_path + "/" + "user_" + std::to_string(_repo_info.map_userinfo[machineid].folder_index);
//                else
//                    folder = _root_path + "/" + "user_" + std::to_string(_repo_info.counter);

                folder = _root_path + "/" + "user_" + machineid;
                return folder;
            }

            bool save_repo()
            {
                if (_root_path.size() == 0) return false;

                std::string filename = _root_path + "/" + REPO_INFO;
                if (file_util::fileexists(filename) == false)
                {
                    std::cerr << "WARNING repo info not found (creating...) " << filename << std::endl;
                }

                // REPO_INFO
                {
                	std::ofstream out;
					out.open(filename, std::ios_base::out);
					out << bits(_repo_info);
					out.close();
                }

                {
                    std::string filenameinfo = _root_path + "/" + USER_INFO;
                    std::ofstream outfile2(filenameinfo);

                    std::stringstream ss;
                    for (auto& c : _repo_info.map_userinfo)
                    {
                        ss
                        << "Folder index: " + std::to_string(c.second.folder_index)
                        << " host: " + c.second.host + " username: " + c.second.usr + "\n";
                    }
                    outfile2 << ss.str();
                    outfile2.close();
                }
                return true;
            }

            bool read_repo()
            {
                if (_root_path.size() == 0) return false;

                std::string filename = _root_path + "/" + REPO_INFO;
                if (file_util::fileexists(filename) == false)
                {
                    std::cerr << "WARNING repo info not found " << filename << std::endl;
                    return false;
                }

                try
                {
                    std::ifstream infile;
                    infile.open (filename, std::ios_base::in);
                    infile >> bits(_repo_info.counter);
                    infile >> bits(_repo_info.map_userinfo);
                    infile.close();
                }
                catch (...)
                {
                    std::cerr << "WARNING repo info can not be read " << filename << std::endl;
                    return false;
                }

                return true;;
            }

            bool set_root(const std::string& root_path, std::string& serr)
            {
                bool r = false;
                if (root_path.size() == 0) return r;

                if (file_util::fileexists(root_path))
                {
                    //check
                    if (std::filesystem::is_directory(root_path))
                    {
                        _root_path = root_path;
                        r = read_repo();
                    }
                    else
                    {
                        serr = "WARNING repo root not a directory " + root_path;
                        r = false;
                    }
                }
                else
                {
                    {
                        bool r = std::filesystem::create_directories(root_path);
                        if (r)
                        {
                            _root_path = root_path;
                        }
                        else
                        {
                            serr = "WARNING can not create the directory " + root_path;
                        }
                    }
                }

                return r;
            }

            bool user_exist(const std::string& machineid, const std::string& in_host, const std::string& in_usr)
            {
                if (_root_path.size() == 0) return false;
                std::string folder = folder_name(machineid, in_host, in_usr);
                return file_util::fileexists(folder);
            }

            bool add_user(const std::string& machineid, const std::string& hostname, const std::string& username)
            {
                if (_root_path.size() == 0)
                    return false;

                if (_repo_info.map_userinfo.contains(machineid))
                {
                    bool changed = false;
                    if (hostname.size() > 0 && _repo_info.map_userinfo[machineid].host.size() == 0)
                    {
                        _repo_info.map_userinfo[machineid].host = hostname;
                        changed = true;
                    }
                    if (username.size() > 0 && _repo_info.map_userinfo[machineid].usr.size() == 0)
                    {
                        _repo_info.map_userinfo[machineid].usr = username;
                        changed = true;
                    }

                    if (changed)
                    {
                        save_repo();
                    }

                    // return....
                }


                std::string folder = folder_name(machineid, hostname, username);
                if (file_util::fileexists(folder))
                {
                    if (std::filesystem::is_directory(folder))
                        return true;
                    return false;
                }

                bool r = std::filesystem::create_directories(folder);
                if (r)
                {
                    //...
                    // add a default url keys file

                    repo_userinfo ur;
                    ur.host = hostname;
                    ur.usr = username;
                    ur.folder_index = _repo_info.counter;

                    _repo_info.map_userinfo[machineid] = ur;
                    _repo_info.counter++;

                    r = save_repo();

#ifdef _WIN32
                    std::string filenamecfg = folder + "\\cfg.ini";
                    r = make_default_crypto_cfg(filenamecfg, folder + "\\");
#else
                    std::string filenamecfg = folder + "/cfg.ini";
                    r = make_default_crypto_cfg(filenamecfg, folder + "/");
#endif
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
                return true;
            }

        };
    }
}

#endif
