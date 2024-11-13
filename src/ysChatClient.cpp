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

//using namespace std;
using namespace ysSocket;

ysClient *chat_client = nullptr;

void signalHandler(int);
void printMessage(const std::string&);

int main(int argc, char** argv) {

	//signal(SIGINT, signalHandler);

	//string server = "localhost";
	std::string server = "127.0.0.1";
	//std::cout << "Server (127.0.0.1 if local): ";
	//std::getline(std::cin, server);
	std::cout << "Port: ";
	int port = 14002;
	std::cin >> port;

	try {

		chat_client = new ysClient(server, port);
		chat_client->setOnMessage(printMessage);
		chat_client->connectServer();

		chat_client->client_UI();

		delete chat_client;

	} catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}

void signalHandler(int code)
{
    chat_client->input_interrupted.store(true);

	char ch;
	std::cout << "Are you sure you want to close socket?(Y/N)";

    std::cin >> ch; // Linux BUG mixing of cin and getchar
	if (toupper(ch) == 'Y' && chat_client != nullptr) {
		delete chat_client;
		exit(0);
	}
	std::cin.clear();
	std::cin.ignore(0x7fffffffffffffff, '\n');

    chat_client->input_interrupted.store(false);
}

void printMessage(const std::string& t_message) {
	std::cout << t_message << std::endl;
}
