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

using namespace std;
using namespace ysSocket;

ysClient *chat_client = nullptr;

void signalHandler(int);
void printMessage(const string&);

int main(int argc, char** argv) {

	//signal(SIGINT, signalHandler);

	//string server = "localhost";
	string server = "127.0.0.1";
	//cout << "Server (127.0.0.1 if local): ";
	//std::getline(std::cin, server);
	//cout << "Port: ";
	int port = 14002;
	//cin >> port;

	try {

		chat_client = new ysClient(server, port);
		chat_client->setOnMessage(printMessage);
		chat_client->connectServer();

		chat_client->writeMessage();

		delete chat_client;

	} catch (const exception& e) {
		cerr << e.what() << endl;
	}

	return 0;
}

void signalHandler(int code)
{
    chat_client->input_interrupted.store(true);

	char ch;
	cout << "Are you sure you want to close socket?(Y/N)";

    cin >> ch; // Linux BUG mixing of cin and getchar
	if (toupper(ch) == 'Y' && chat_client != nullptr) {
		delete chat_client;
		exit(0);
	}
	cin.clear();
	cin.ignore(0x7fffffffffffffff, '\n');

    chat_client->input_interrupted.store(false);
}

void printMessage(const string& t_message) {
	std::cout << t_message << std::endl;
}
