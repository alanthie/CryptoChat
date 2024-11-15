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
cryptochat::srv::chat_srv* global_srv = nullptr;

int main(int argc, char** argv)
{
	std::string FULLVERSION = CHATSRV_VERSION + "_" + cryptoAL::parsing::get_current_date();

	// Argument parser
	try
	{
		argparse::ArgumentParser program("chatsrv", FULLVERSION);
		{
			program.add_description("Run chat server");

			program.add_argument("-cfg", "--cfg")
				.default_value(std::string(""))
				.help("specify a config file.");
		}


//		argparse::ArgumentParser run_command("run");
//		{
//			run_command.add_description("Run chat server");
//
//			run_command.add_argument("-cfg", "--cfg")
//				.default_value(std::string(""))
//				.help("specify a config file.");
//		}

		// Add the subcommands to the main parser
		//program.add_subparser(run_command);

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

			global_srv = new cryptochat::srv::chat_srv(cfg);
			return global_srv->run();
		}

//		if (program.is_subcommand_used("run"))
//		{
//			auto& cmd = run_command;
//			auto cfg = cmd.get<std::string>("--cfg");
//
//			global_srv = new cryptochat::srv::chat_srv(cfg);
//			return global_srv->run();
//		}

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
