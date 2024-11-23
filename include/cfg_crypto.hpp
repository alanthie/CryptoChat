#pragma once
#ifndef cfg_crypto_H_INCLUDED
#define cfg_crypto_H_INCLUDED

#include <string>
#include <map>
#include "../include/c_plus_plus_serializer.h"
#include "../include/file_util.hpp"
#include "../include/ini_parser.hpp"

//;
//; cfg.ini
//;
//; . / crypto encode - cfg . / cfg.ini - i msg.zip
//; . / crypto decode - cfg . / cfg.ini - i msg.zip.encrypted
//;
//
//[var]
//var_folder_me_and_other = / home / server / dev / Encryptions / testcase / test / AL /
//
//[cmdparam]
//filename_urls = urls.txt
//filename_msg_data = msg.zip
//filename_puzzle =
//filename_full_puzzle =
//filename_encrypted_data = msg.zip.encrypted
//filename_decrypted_data =
//keeping = 0
//folder_local = <var_folder_me_and_other>sam / local /
//folder_my_private_rsa = <var_folder_me_and_other>me /
//folder_other_public_rsa = <var_folder_me_and_other>sam /
//folder_my_private_ecc = <var_folder_me_and_other>me /
//folder_other_public_ecc = <var_folder_me_and_other>sam /
//folder_my_private_hh = <var_folder_me_and_other>me /
//folder_other_public_hh = <var_folder_me_and_other>sam /
//wbaes_my_private_path = <var_folder_me_and_other>
//wbaes_other_public_path = <var_folder_me_and_other>
//encryped_ftp_user =
//encryped_ftp_pwd =
//known_ftp_server =
//auto_flag =
//use_gmp = 1
//self_test = 0
//key_size_factor = 3
//shufflePerc = 0
//converter =
//check_converter =
//verbose = 1
//
//[keymgr]
//max_usage1 = keytype:rsa, bits : 64, max_usage_count : 1
//max_usage2 = keytype : rsa, bits : 1024, max_usage_count : 16
//
//[keygen]
//policy1 = keytype : rsa, pool_first : 10, pool_random : 30, pool_last : 10, pool_new : 20, pool_max : 100
//
//[algo]
//ALGO_BIN_AES_128_ecb = 0
//ALGO_BIN_AES_128_cbc = 0
//ALGO_BIN_AES_128_cfb = 1
//ALGO_BIN_AES_256_ecb = 1
//ALGO_BIN_AES_256_cbc = 1
//ALGO_BIN_AES_256_cfb = 1
//ALGO_TWOFISH = 1
//ALGO_Salsa20 = 1
//ALGO_IDEA = 1
//ALGO_wbaes512 = 1
//ALGO_wbaes1024 = 1
//ALGO_wbaes2048 = 1
//ALGO_wbaes4096 = 1
//ALGO_wbaes8192 = 1
//ALGO_wbaes16384 = 1
//ALGO_wbaes32768 = 1

namespace cryptochat
{
	namespace cfg
	{
        struct cfg_crypto_params
        {
            std::string filename_urls;
            std::string filename_msg_data;
            std::string filename_puzzle;
            std::string filename_full_puzzle;
            std::string filename_encrypted_data;
            std::string filename_decrypted_data;

            std::string keeping;

            std::string folder_local;
            std::string folder_my_private_rsa;
            std::string folder_other_public_rsa;
            std::string folder_my_private_ecc;
            std::string folder_other_public_ecc;
            std::string folder_my_private_hh;
            std::string folder_other_public_hh;
            std::string wbaes_my_private_path;
            std::string wbaes_other_public_path;

            std::string encryped_ftp_user;
            std::string encryped_ftp_pwd;
            std::string known_ftp_server;

            std::string auto_flag;
            std::string use_gmp;
            std::string self_test;
            std::string key_size_factor;
            std::string shufflePerc;
            std::string converter;
            std::string check_converter;
            std::string verbose;

            size_t sz = 0;
            long ikeyfactor = 1;
        };

		struct cfg_crypto
		{
            const std::string Config = "cmdparam";
            cfg_crypto_params _p;
 
            bool read(const std::string& inifile, std::string&  serr, bool verbose_mode)
            {
                bool r = false;
                if (file_util::fileexists(inifile) == false)
                {
                    serr += "ERROR config file not found:" + inifile + "\n";
                    return false;
                }

                ini_parser ini(inifile);
                std::map<std::string, std::map<std::string, std::string>>& map_sections = ini.get_sections();

                if (map_sections.find(Config) == map_sections.end())
                {
                    serr += "ERROR no cmdparam section in config file: " + inifile + "\n";
                    return false;
                }
                else
                {
                    _p.filename_urls = ini.get_string("filename_urls", Config);
                    _p.filename_msg_data = ini.get_string("filename_msg_data", Config);
                    _p.filename_puzzle = ini.get_string("filename_puzzle", Config);
                    _p.filename_full_puzzle = ini.get_string("filename_full_puzzle", Config);
                    _p.filename_urls = ini.get_string("filename_urls", Config);
                    _p.filename_msg_data = ini.get_string("filename_msg_data", Config);
                    _p.filename_puzzle = ini.get_string("filename_puzzle", Config);
                    _p.filename_full_puzzle = ini.get_string("filename_full_puzzle", Config);
                    _p.filename_encrypted_data = ini.get_string("filename_encrypted_data", Config);
                    _p.filename_decrypted_data = ini.get_string("filename_decrypted_data", Config);
                    _p.keeping = ini.get_string("keeping", Config);
                    _p.folder_local = ini.get_string("folder_local", Config);
                    _p.folder_my_private_rsa = ini.get_string("folder_my_private_rsa", Config);
                    _p.folder_other_public_rsa = ini.get_string("folder_other_public_rsa", Config);
                    _p.folder_my_private_ecc = ini.get_string("folder_my_private_ecc", Config);
                    _p.folder_other_public_ecc = ini.get_string("folder_other_public_ecc", Config);
                    _p.folder_my_private_hh = ini.get_string("folder_my_private_hh", Config);
                    _p.folder_other_public_hh = ini.get_string("folder_other_public_hh", Config);
                    _p.wbaes_my_private_path = ini.get_string("wbaes_my_private_path", Config);
                    _p.wbaes_other_public_path = ini.get_string("wbaes_other_public_path", Config);
                    _p.encryped_ftp_user = ini.get_string("encryped_ftp_user", Config);
                    _p.encryped_ftp_pwd = ini.get_string("encryped_ftp_pwd", Config);
                    _p.known_ftp_server = ini.get_string("known_ftp_server", Config);
                    _p.auto_flag = ini.get_string("auto_flag", Config);
                    _p.use_gmp = ini.get_string("use_gmp", Config);
                    _p.self_test = ini.get_string("self_test", Config);
                    _p.key_size_factor = ini.get_string("key_size_factor", Config);
                    _p.shufflePerc = ini.get_string("shufflePerc", Config);
                    _p.converter = ini.get_string("converter", Config);
                    _p.check_converter = ini.get_string("check_converter", Config);
                    _p.verbose = ini.get_string("verbose", Config);

                    //if (std::filesystem::exists(folder_staging) == false)
                    //{
                    //    std::filesystem::create_directories(folder_staging);
                    //}
                }

                _p.sz = 0;
                _p.ikeyfactor = 1;
                try
                {
                    if (_p.key_size_factor.size() == 0)
                    {
                        _p.ikeyfactor = 1;
                    }
                    else
                    {
                        _p.ikeyfactor = std::stol(_p.key_size_factor, &_p.sz);
                    }
                }
                catch (...)
                {
                    serr += "Warning invalid keyfactor format, keyfactor reset to 1\n";
                    _p.ikeyfactor = 1;
                }

                return r;
            }


			//bool save(const std::string& filename, std::string& serr)
			//{
			//	if (filename.size() == 0)
			//	{
			//		serr += "WARNING save_cfg - cfg file name empty: ";
			//		return false;
			//	}

			//	try
			//	{
   //                 //...
			//	}
			//	catch (const std::exception& e)
			//	{
			//		serr += "WARNING save_cfg - unable to save file " + filename + "\n";
			//		serr += "Exception thrown: " + std::string(e.what()) + "\n";
			//	}
			//	catch (...)
			//	{
			//		serr += "WARNING save_cfg - unable to save file " + filename + "\n";
			//		serr += "Exception thrown\n";
			//	}
			//	return false;
			//}
		};
	}
}

#endif

