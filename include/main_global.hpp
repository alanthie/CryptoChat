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

	static void log(const std::string s)
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			std::stringstream& ss = log_stream();
			ss << s;
			log_is_dirty = true;
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

private:
	static std::stringstream log_ss;
	static std::mutex log_mutex;
	static bool log_is_dirty;

	static std::stringstream& log_stream()
	{
		return main_global::log_ss;
	};
};
