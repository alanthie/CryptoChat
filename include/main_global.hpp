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

        cryptochat::cli::chat_cli::got_chat_cli_signal = 1;
        //delete main_global::global_cli// thread will join on itself = bug

        std::string key;
        key = main_global::global_cli->_chat_cli->get_key();

        NETW_MSG::MSG m;
        m.make_msg(NETW_MSG::MSG_CMD_RESP_SHUTDOWN, "shutdown", key);

        bool crypto_on = (main_global::global_cli->_chat_cli->cryto_on == true) ? true : false;
        if (main_global::global_cli->_chat_cli->chat_with_other_user_index == 0) crypto_on = false;

        int ret = main_global::global_cli->_chat_cli->send_message_buffer(  main_global::global_cli->_chat_cli->get_socket(), m, key,
                                                        crypto_on,
                                                        main_global::global_cli->_chat_cli->my_user_index,
                                                        main_global::global_cli->_chat_cli->chat_with_other_user_index);

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
