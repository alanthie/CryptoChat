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

using namespace std;
using namespace ysSocket;

ysServer *chat_server = nullptr;

void signalHandler(int);
void printMessage(const string&);

int main(int argc, char** argv) {

	signal(SIGINT, signalHandler);

	int port = 14002;
	//cout << "Port: ";
	//cout << port << std::endl;
	//cin >> port;
	//cout << "Connection (1-128): ";
	int connection_size = 128;
	//cout << connection_size << std::endl;
	//cin >> connection_size;

	try {
		chat_server = new ysServer(port, connection_size);
		chat_server->setOnMessage(printMessage);
		chat_server->runServer();

		delete chat_server;

	} catch (const exception& e) {
		cerr << e.what() << endl;
	}

	std::this_thread::sleep_for(std::chrono::seconds(5));
	return 0;
}

void signalHandler(int code) {
	char ch;
	cout << "Are you sure you want to close socket?(Y/N)";
	cin >> ch;
	if (toupper(ch) == 'Y' && chat_server != nullptr) {
		delete chat_server;
		exit(0);
	}
	cin.clear();
	//cin.ignore(numeric_limits<streamsize>::max(), '\n');
	cin.ignore(0x7fffffffffffffff, '\n');
}

void printMessage(const string& t_message) {
	std::cout << t_message << std::endl;
}
