#pragma once
#ifndef Repository_H_INCLUDED
#define Repository_H_INCLUDED

#include <string>
#include <map>
#include "../include/file_util.hpp"
#include "../include/c_plus_plus_serializer.h"

// RSA
#include "../include/crypto_parsing.hpp"
#include "../include/qa/rsa_gen.hpp"
#include "../include/cfg_crypto.hpp"

#ifdef _WIN32
//add preprocessor directive NOMINMAX
#pragma warning ( disable : 4146 )
#endif
#include "../include/qa/RSA-GMP/RSAGMPTest.h"


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
                    serr += "WARNING save_repo - empty repo root pathname\n";
                    return false;
                }

                std::string filename = _root_path + file_separator() + REPO_INFO;
                if (file_util::fileexists(filename) == false)
                {
                    serr += "WARNING save_repo - repo info not found (creating...) " + filename + "\n";
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
                    serr += "WARNING read_repo - empty repo root pathname\n";
                    return false;
                }

                std::string filename = _root_path + file_separator() + REPO_INFO;
                if (file_util::fileexists(filename) == false)
                {
                    serr += "WARNING read_repo - repo info not found (no user registered so far) " + filename + "\n";
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
                    serr += "WARNING read_repo - repo info can not be read " + filename + "\n";
                    return false;
                }

                return true;;
            }

            bool set_root(const std::string& root_path, std::string& serr)
            {
                bool r = false;
                if (root_path.size() == 0)
                {
                    serr += "ERROR set_root - empty repo root pathname\n";
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
                        serr += "ERROR set_root - repo root not a directory " + root_path + "\n";
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
                            serr += "ERROR set_root - can not create the repo root directory " + root_path + "\n";
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
                    serr += "WARNING add_me - empty repo root pathname \n";
                    return false;
                }

                std::string folder = folder_me();
                if (file_util::fileexists(folder))
                {
                    if (std::filesystem::is_directory(folder))
                        return true;

                    serr += "WARNING add_me - me folder is not a directory " + folder + "\n";
                    return false;
                }

                r = std::filesystem::create_directories(folder);
                if (r)
                {
                    if (std::filesystem::is_directory(folder))
                        return true;

                    serr += "WARNING add_me - me folder is not a directory " + folder + "\n";
                    return false;
                }
                else
                {
                    serr += "WARNING add_me - Unable to create me folder " + folder + "\n";
                }
                return r;
            }

            bool add_user(uint32_t user_index, const std::string& hostname, const std::string& username, std::string& serr)
            {
                bool r = true;
                if (_root_path.size() == 0)
                {
                    serr += "WARNING add_user - empty repo root pathname\n";
                    return false;
                }

                if (_repo_info.map_userinfo.contains(user_index))
                {
                    bool changed = false;
                    if (hostname != _repo_info.map_userinfo[user_index].host)
                    {
                        _repo_info.map_userinfo[user_index].host = hostname;
                        changed = true;
                    }
                    if (username != _repo_info.map_userinfo[user_index].usr)
                    {
                        _repo_info.map_userinfo[user_index].usr = username;
                        changed = true;
                    }

                    if (changed)
                    {
                       r = save_repo(serr);
                       if (!r)
                       {
                          /// return false;
                       }
                    }
                }

                std::string folder = folder_name(user_index, hostname, username);
                if (file_util::fileexists(folder))
                {
                    if (std::filesystem::is_directory(folder))
                        return true;

                    serr += "WARNING add_user - user folder is not a directory " + folder + "\n";
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
                            serr += "WARNING add_user - Unable to create file " + filenamecfg +  "\n";
                        }
                        else
                        {
                            std::string filenameurls = folder + file_separator() + "urls.txt";
                            r = make_default_urls(filenameurls, folder + file_separator());
                            if (!r)
                            {
                                serr += "WARNING add_user - Unable to create file " + filenameurls + "\n";
                            }
                        }
                    }

                    if (r)
                    {
                        std::stringstream ss;
                        std::string filenamecfg = folder + file_separator() + "cfg.ini";

                        cryptochat::cfg::cfg_crypto cc;
                        r = cc.read(filenamecfg, serr, false);

                        if (r)
                        {
                            //----------------------
                            // RSA private keys generation
                            //----------------------
                            if (file_util::fileexists(cc._p.folder_my_private_rsa) == false)
                            {
                                std::filesystem::create_directories(cc._p.folder_my_private_rsa);
                            }

                            r = genrsa(ss, 2024, cc._p.folder_my_private_rsa); /*folder_my_private_rsa*/
                            if (r)
                            {
                                serr += "\n";
                                serr += "INFO - Private RSA key added to repository index: " + std::to_string(user_index) +  "\n";
                            }
                            else
                            {
                                serr += "WARNING add_user - Unable to generate RSA key at " +  cc._p.folder_my_private_rsa + "\n";
                            }

                            //----------------------
                            // RSA public keys export
                            //----------------------
                            if (r)
                            {
                                r = exportrsa(ss, cc._p.folder_my_private_rsa);
                                if (r)
                                {
                                    serr += "\n";
                                    serr += "INFO - Public RSA  exported in repository index: " + std::to_string(user_index) + "\n";
                                }
                                else
                                {
                                    serr += "WARNING add_user - Unable to export RSA key at " + folder + file_separator() + cc._p.folder_my_private_rsa + "\n";
                                }
                            }
                        }
                        else
                        {
                            serr += "WARNING add_user - Unable to read cfg " + filenamecfg + "\n";
                        }

                        serr += ss.str();
                    };
                }
                else
                {
                    // Multiple instance on same machine... TODO
                    if (file_util::fileexists(folder) == false)
                        serr += "WARNING add_user - Unable to create user folder " + folder + "\n";
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
                ss << "filename_decrypted_data = msg.zip.decrypted";  ss << "\n";
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
                ss << "auto_flag = 1"; ss << "\n";
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
                ss << "[r:]last=1,first=1,random=1;\n";
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



            long long keybits8x(long long bits)
            {
                if (bits % 8 != 0)
                {
                    bits += (8 - (bits % 8));
                }
                return bits;
            }

            // RSA Key: Generate RSA key with GMP (fast)
            bool genrsa(std::stringstream& ss, long long klen, const std::string& folder_my_private_rsa)
            {
                int r = 0;
                bool rr = true;
                cryptoAL::rsa::PRIVATE_KEY key;

                // rsa key length in bits (0 = defaut = 2048): ";
                if (klen <= 0) klen = 2048;
                klen = keybits8x(klen);

                std::string fileRSADB;
                fileRSADB = folder_my_private_rsa + file_separator() + cryptoAL::RSA_MY_PRIVATE_DB;

                int nt = std::thread::hardware_concurrency();
                ss << "RSA key generator using " << nt << " threads" << std::endl;

                RSAGMP::Utils::TestGenerator generator;

                RSAGMP::Utils::mpzBigInteger pub;
                RSAGMP::Utils::mpzBigInteger priv;
                RSAGMP::Utils::mpzBigInteger modulus;
                rr = RSAGMP::get_keys((unsigned int)klen, &generator, nt, 20, pub, priv, modulus);
                if (rr)
                {
                    std::string s_n(modulus.get_str());
                    std::string s_e(pub.get_str());
                    std::string s_d(priv.get_str());

                    cryptoAL::rsa::rsa_key k;
                    cryptoAL::rsa::rsa_key rkey(2, (int)klen,
                        uint_util::base10_to_base64(s_n),
                        uint_util::base10_to_base64(s_e),
                        uint_util::base10_to_base64(s_d));

                    // READ
                    std::map< std::string, cryptoAL::rsa::rsa_key> map_rsa_private;

                    if (file_util::fileexists(fileRSADB) == false)
                    {
                        std::ofstream outfile;
                        outfile.open(fileRSADB, std::ios_base::out);
                        outfile.close();
                    }

                    if (file_util::fileexists(fileRSADB) == true)
                    {
                        std::ifstream infile;
                        infile.open(fileRSADB, std::ios_base::in);
                        infile >> bits(map_rsa_private);
                        infile.close();
                    }
                    else
                    {
                        ss << "ERROR no file: " << fileRSADB << std::endl;
                        r = -1;
                        rr = false;
                    }

                    if (r >= 0)
                    {
                        // backup
                        {
                            std::ofstream outfile;
                            outfile.open(fileRSADB + ".bck", std::ios_base::out);
                            outfile << bits(map_rsa_private);
                            outfile.close();
                        }

                        std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + cryptoAL::parsing::get_current_time_and_date();
                        map_rsa_private.insert(std::make_pair(keyname, rkey));

                        {
                            std::ofstream outfile;
                            outfile.open(fileRSADB, std::ios_base::out);
                            outfile << bits(map_rsa_private);
                            outfile.close();
                        }
                        ss << "RSA key saved as: " << keyname << std::endl;
                    }
                }
                return rr;
            }

            bool exportrsa(std::stringstream& ss, const std::string& folder_my_private_rsa)
            {
                // RSA Key: Export my public RSA key

                int r = 0;
                std::string fileRSADB;
                std::string pathdb;

                fileRSADB           = folder_my_private_rsa + file_separator()  + cryptoAL::RSA_MY_PRIVATE_DB;
                std::string outfile = folder_my_private_rsa + file_separator()  + cryptoAL::RSA_MY_PUBLIC_DB;
                ss << "Public rsa keys would be saved in: " << outfile << std::endl;

                std::map< std::string, cryptoAL::rsa::rsa_key > map_RSA_private;
                std::map< std::string, cryptoAL::rsa::rsa_key > map_RSA_public;

                if (file_util::fileexists(fileRSADB) == true)
                {
                    std::ifstream infile;
                    infile.open(fileRSADB, std::ios_base::in);
                    infile >> bits(map_RSA_private);
                    infile.close();

                    for (auto& [keyname, k] : map_RSA_private)
                    {
                        cryptoAL::rsa::rsa_key key_public;
                        key_public.key_size_in_bits = k.key_size_in_bits;
                        key_public.s_n = k.s_n;
                        key_public.s_e = k.s_e;
                        key_public.s_d = "";

                        map_RSA_public.insert(std::make_pair(keyname, key_public));
                    }

                    ss << "---------------------------" << std::endl;
                    ss << "Summary of " << outfile << std::endl;
                    ss << "---------------------------" << std::endl;
                    for (auto& [keyname, k] : map_RSA_public)
                    {
                        ss << keyname << std::endl;
                    }
                    ss << std::endl;

                    {
                        std::ofstream out;
                        out.open(outfile, std::ios_base::out);
                        out << bits(map_RSA_public);
                        out.close();
                    }
                }
                else
                {
                    ss << "no file: " << fileRSADB << std::endl;
                    r = -1;
                    return false;
                }
                return true;
            }

        };
    }
}

#endif
