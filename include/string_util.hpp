#ifndef NETW_STRUTIL_H
#define NETW_STRUTIL_H

#include <cstring>
#include <iostream>
#include <string>
#include <vector>


namespace NETW_MSG
{
	[[maybe_unused]] static long long str_to_ll(const std::string& snum)
	{
		long long r = -1;
		try
		{
			r = std::stoll(snum);
		}
		catch (...)
		{
			r = -1;
		}
		return r;
	}

	[[maybe_unused]] static std::string get_input_string()
	{
		std::string r;
		std::cin >> r;
		std::cin.ignore(10000, '\n');
		std::cin.clear();
		return r;
	}

	[[maybe_unused]] static std::vector<std::string> split(std::string& s, const std::string& delimiter)
	{
		std::vector<std::string> tokens;
		size_t pos = 0;
		std::string token;
		while ((pos = s.find(delimiter)) != std::string::npos) {
			token = s.substr(0, pos);
			tokens.push_back(token);
			s.erase(0, pos + delimiter.length());
		}
		tokens.push_back(s);
		return tokens;
	}

}

#endif
