/*
 * Author: Alain Lanthier
 */

//g++ -c ysClient.cpp ysNodeV4.cpp ysServer.cpp ysChatClient.cpp ysChatServer.cpp -std=c++17
//g++ -o runserver ysClient.o ysNodeV4.o ysServer.o ysChatServer.o  -std=c++17 -pthread

#include <iostream>
#include <limits>
#include <csignal>
#include <chrono>
#include "../include/ysServer.h"
#include "../include/chat_srv.hpp"
#include "../include/cfg_srv.hpp"
#include "../include/string_util.hpp"
#include "../include/argparse.hpp"
#include "../include/crypto_parsing.hpp"

const std::string CHATSRV_VERSION = "0.1";

class main_global
{
public:
	static cryptochat::srv::chat_srv* global_srv;
};
cryptochat::srv::chat_srv*  main_global::global_srv = nullptr;

static void signalHandler(int code)
{
	char ch;
	std::cout << "Are you sure you want to close server? (y/n)";
	std::cin >> ch;
	if (toupper(ch) == 'Y') 
	{
		if (main_global::global_srv != nullptr)
		try
		{
			delete main_global::global_srv;
		}
		catch (...)
		{
		}
  		exit(0);
	}
	std::cin.clear();
	std::cin.ignore(0x7fffffffffffffff, '\n');
}


int main(int argc, char** argv)
{
	std::string FULLVERSION = CHATSRV_VERSION + "_" + cryptoAL::parsing::get_current_date();

	// Argument parser
	try
	{
		signal(SIGINT, signalHandler);

		argparse::ArgumentParser program("chatsrv", FULLVERSION);
		{
			program.add_description("Run chat server");

			program.add_argument("-cfg", "--cfg")
				.default_value(std::string(""))
				.help("specify a config file.");
		}

		// Parse the arguments
		try
		{
			program.parse_args(argc, argv);
		}
		catch (const std::runtime_error& err)
		{
			std::cerr << err.what() << std::endl;
			std::cerr << program;
			return -1;
		}

		{
			auto& cmd = program;
			auto cfg = cmd.get<std::string>("--cfg");

			main_global::global_srv = new cryptochat::srv::chat_srv(cfg);
			return main_global::global_srv->run();
		}

	}
	catch (std::invalid_argument const& ex)
	{
		std::cerr << "CHATSRV FAILED - invalid_argument thrown " << ex.what() << '\n';
	}
	catch (std::logic_error const& ex)
	{
		std::cerr << "CHATSRV FAILED - logic_error thrown " << ex.what() << '\n';
	}
	catch (std::range_error const& ex)
	{
		std::cerr << "CHATSRV FAILED - range_error thrown " << ex.what() << '\n';
	}
	catch (std::runtime_error const& ex)
	{
		std::cerr << "CHATSRV FAILED - runtime_error thrown " << ex.what() << '\n';
	}
	catch (std::exception const& ex)
	{
		std::cerr << "CHATSRV FAILED - std exception thrown " << ex.what() << '\n';
	}
	catch (...)
	{
		std::cerr << "CHATSRV FAILED - exception thrown" << std::endl;
	}
	return 0;
}
