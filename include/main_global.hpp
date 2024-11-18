#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <mutex>
#include "../include/chat_cli.hpp"

class main_global
{
public:
	static cryptochat::cli::chat_cli* global_cli;

	static void log(const std::string s, bool show_in_console = false)
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			std::stringstream& ss = log_stream();
			ss << s;
			log_is_dirty = true;

			if (show_in_console)
			{
                std::cout << s;
			}
		}
	};

	static bool is_log_dirty()
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			bool b = log_is_dirty;
			return b;
		}
	}
	static void set_log_dirty(bool b)
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			log_is_dirty = b;
		}
	}

	static std::string get_log_string()
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			auto& ss = main_global::log_stream();
			std::string s = ss.str();
			return s;
		}
	}

	static void shutdown()
	{
        main_global::log("shutdown", true);

		if (main_global::global_cli != nullptr)
		{
			try
			{
				cryptochat::cli::chat_cli::got_chat_cli_signal = 1;
				std::this_thread::sleep_for(std::chrono::seconds(1));

				delete main_global::global_cli;
				main_global::global_cli = nullptr;
			}
			catch (...)
			{
			}
		}
	}

private:
	static std::stringstream log_ss;
	static std::mutex log_mutex;
	static bool log_is_dirty;

	static std::stringstream& log_stream()
	{
		return main_global::log_ss;
	};
};
