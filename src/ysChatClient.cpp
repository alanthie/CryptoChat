/*
 * Author: Alain Lanthier
 */

// g++ -c ysClient.cpp ysNodeV4.cpp ysServer.cpp ysChatClient.cpp ysChatServer.cpp -std=c++17
//

#include <iostream>
#include <string>
#include <limits>
#include <csignal>
#include "../include/ysClient.h"
#include "../include/string_util.hpp"
#include "../include/chat_cli.hpp"
#include "../include/cfg_cli.hpp"
#include "../include/string_util.hpp"
#include "../include/argparse.hpp"
#include "../include/crypto_parsing.hpp"

const std::string CLI_VERSION = "0.1";
cryptochat::cli::chat_cli* global_cli = nullptr;

int main(int argc, char** argv)
{
	std::string FULLVERSION = CLI_VERSION + "_" + cryptoAL::parsing::get_current_date();

	// Argument parser
	try
	{
		argparse::ArgumentParser program("chatcli", FULLVERSION);
		{
			program.add_description("Run chat client");

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

        auto& cmd = program;
        auto cfg = cmd.get<std::string>("--cfg");

        global_cli = new cryptochat::cli::chat_cli(cfg);
        return global_cli->run();
	}
	catch (std::invalid_argument const& ex)
	{
		std::cerr << "CHATCLI FAILED - invalid_argument thrown " << ex.what() << '\n';
	}
	catch (std::logic_error const& ex)
	{
		std::cerr << "CHATCLI FAILED - logic_error thrown " << ex.what() << '\n';
	}
	catch (std::range_error const& ex)
	{
		std::cerr << "CHATCLI FAILED - range_error thrown " << ex.what() << '\n';
	}
	catch (std::runtime_error const& ex)
	{
		std::cerr << "CHATCLI FAILED - runtime_error thrown " << ex.what() << '\n';
	}
	catch (std::exception const& ex)
	{
		std::cerr << "CHATCLI FAILED - std exception thrown " << ex.what() << '\n';
	}
	catch (...)
	{
		std::cerr << "CHATCLI FAILED - exception thrown" << std::endl;
	}
	return 0;
}

