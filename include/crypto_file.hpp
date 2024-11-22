#ifndef _INCLUDES_crypto_file
#define _INCLUDES_crypto_file

#include "crypto_const.hpp"
#include "crypto_parsing.hpp"
#include <curl/curl.h>
#include "encrypt.h" //decrypt_simple_string

namespace cryptoAL
{
namespace key_file
{
	static std::string s_last_local_file = "";
	static bool s_use_last = false;

	int wget(const char *in, const char *out, bool verbose);

	int getvideo(std::string url, std::string outfile, std::string options = "", [[maybe_unused]] bool verbose = false);

	int getlocal(std::string url, cryptodata& dataout, std::string options = "", [[maybe_unused]] bool verbose = false);
	
	int getftp(std::string url, std::string outfile,
		std::string encryped_ftp_user,
		std::string encryped_ftp_pwd,
		std::string known_ftp_server,
		std::string options = "", bool verbose = false);

	size_t write(void* ptr, size_t size, size_t nmemb, FILE* stream);
	int wget(const char* in, const char* out, [[maybe_unused]] bool verbose = false);
}
}
#endif


