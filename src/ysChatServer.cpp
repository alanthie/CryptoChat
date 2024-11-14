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
#include "../include/string_util.hpp"

//using namespace std;
using namespace ysSocket;

ysServer *chat_server = nullptr;

void signalHandler(int);
void printMessage(const std::string&);

int main(int argc, char** argv) {

	signal(SIGINT, signalHandler);

	std::string entry;
	int port = 14003;
	std::cout << "Port (Default 14003): ";
	std::getline(std::cin, entry); if (!entry.empty()) port = (int)NETW_MSG::str_to_ll(entry);

	std::cout << "Connection (1-128) (Default 32): ";
	int connection_size = 32;
	std::getline(std::cin, entry); if (!entry.empty()) connection_size = (int)NETW_MSG::str_to_ll(entry);

	std::cout << "Port : " << port << std::endl;
	std::cout << "Connection : " << connection_size << std::endl;

	try {
		chat_server = new ysServer(port, connection_size);
		chat_server->setOnMessage(printMessage);
		chat_server->runServer();

		delete chat_server;

	} catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

	std::this_thread::sleep_for(std::chrono::seconds(5));
	return 0;
}

void signalHandler(int code) {
	char ch;
	std::cout << "Are you sure you want to close socket?(Y/N)";
	std::cin >> ch;
	if (toupper(ch) == 'Y' && chat_server != nullptr) {
		delete chat_server;
		exit(0);
	}
	std::cin.clear();
	//cin.ignore(numeric_limits<streamsize>::max(), '\n');
	std::cin.ignore(0x7fffffffffffffff, '\n');
}

void printMessage(const std::string& t_message) {
	std::cout << t_message << std::endl;
}
