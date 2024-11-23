/*
 * Author: Alain Lanthier
 */

// g++ -c ysClient.cpp ysNodeV4.cpp ysServer.cpp ysChatClient.cpp ysChatServer.cpp -std=c++17
//

#include <iostream>
#include <string>
#include <sstream>
#include <limits>
#include <csignal>

#include "../include/crypto_const.hpp"
#include "../include/ysClient.h"
#include "../include/string_util.hpp"
#include "../include/chat_cli.hpp"
#include "../include/cfg_cli.hpp"
#include "../include/string_util.hpp"
#include "../include/argparse.hpp"
#include "../include/crypto_parsing.hpp"
#include "../include/main_global.hpp"

const std::string CLI_VERSION = "0.1";

std::atomic<int> cryptochat::cli::chat_cli::got_chat_cli_signal = 0;

cryptochat::cli::chat_cli* main_global::global_cli = nullptr;

std::stringstream	main_global::main_global::log_ss;
std::mutex			main_global::log_mutex;
bool				main_global::log_is_dirty = true;

static void signalHandler(int code)
{
    main_global::shutdown();
    //exit(0);
}

int main(int argc, char** argv)
{
	std::string FULLVERSION = CLI_VERSION;// + "_" + cryptoAL::parsing::get_current_date();

	// Argument parser
	try
	{
		signal(SIGINT, signalHandler);

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

		std::string serr;
        auto& cmd = program;
        auto cfg = cmd.get<std::string>("--cfg");

		main_global::global_cli = new cryptochat::cli::chat_cli(cfg);
        return main_global::global_cli->run(serr);
	}
	catch (std::invalid_argument const& ex)
	{
		std::stringstream ss;
		ss << "CHATCLI FAILED - invalid_argument thrown " << ex.what() << '\n';
		main_global::log(ss.str(),true);
	}
	catch (std::logic_error const& ex)
	{
		std::stringstream ss;
		ss << "CHATCLI FAILED - logic_error thrown " << ex.what() << '\n';
		main_global::log(ss.str(),true);
	}
	catch (std::range_error const& ex)
	{
		std::stringstream ss;
		ss << "CHATCLI FAILED - range_error thrown " << ex.what() << '\n';
		main_global::log(ss.str()),true;
	}
	catch (std::runtime_error const& ex)
	{
		std::stringstream ss;
		ss << "CHATCLI FAILED - runtime_error thrown " << ex.what() << '\n';
		main_global::log(ss.str(),true);
	}
	catch (std::exception const& ex)
	{
		std::stringstream ss;
		ss << "CHATCLI FAILED - std exception thrown " << ex.what() << '\n';
		main_global::log(ss.str(),true);
	}
	catch (...)
	{
		std::stringstream ss;
		ss << "CHATCLI FAILED - exception thrown" << std::endl;
		main_global::log(ss.str()), true;
	}
	return 0;
}

