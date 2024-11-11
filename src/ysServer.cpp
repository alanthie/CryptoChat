/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <string>
#include "../include/ysServer.h"
#include "../include/SHA256.h"
#include "../include/crc32a.hpp"

#ifdef _WIN32
#pragma warning(disable : 4996)
#endif

namespace ysSocket {

	void ysServer::setDefault() {
		this->m_socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	void ysServer::showMessage(const std::string& t_message) {
		if (this->m_onMessage != nullptr) {
			std::lock_guard<std::mutex> locker(this->m_mu);
			this->m_onMessage(t_message);
		}
	}

	ysServer::ysServer() : ysNodeV4() {
		setDefault();
	}

	ysServer::ysServer(const int& t_port) : ysNodeV4(t_port) {
		setDefault();
	}

	ysServer::ysServer(const int& t_port, const int& t_connectionSize) : ysNodeV4(t_port), m_connectionSize(t_connectionSize) {
		setDefault();
	}

	void ysServer::setOnMessage(const std::function<void(const std::string&)>& t_function) {
		m_onMessage = t_function;
	}

	void ysServer::runServer()
	{
		this->createServer();
		this->bindServer();
		this->listenServer();

		{
			std::string key("key012345679");
			if (this->check_default_encrypt(key) == false)
			{
				throw std::runtime_error("Default encryption not working");
			}

			key = getDEFAULT_KEY();
			if (this->check_default_encrypt(key) == false)
			{
				throw std::runtime_error("Default key encryption not working");
			}

			// TEST cryptoAL_vigenere
			for(int i=0;i<1;i++)
			{
				std::string bkey = cryptoAL::random::generate_base64_random_string(KEY_SIZE);

				//BASEDIGIT64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+="; // NOT STANDARD
				//for (int j = 0; j < bkey.size(); j++)
				//{
				//	if (bkey[j] == '+') bkey[j] = 'a';
				//	if (bkey[j] == '=') bkey[j] = 'b';
				//}
				//AVAILABLE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

				std::string bdat = cryptoAL::random::generate_base64_random_string(KEY_SIZE / 2);
				std::string benc = cryptoAL_vigenere::encrypt_vigenere(bdat, bkey);
				std::string bdec = cryptoAL_vigenere::decrypt_vigenere(benc, bkey);
				if (bdat != bdec)
				{
					throw std::runtime_error("Vigenere key encryption not working on Base64");
				}
			}

			// TEST IDEA
			{
				idea id;

				uint16_t data[4] = { 54,36,454,345 };
				uint16_t key[8] = { 345,3453,5,3453,5,3556,46,4567 };
				id.IDEA(data, key, true);
				id.IDEA(data, key, false);
			}
			for(int i=0;i<1;i++)
			{
				std::string bkey = cryptoAL::random::generate_base64_random_string(KEY_SIZE/8);
				std::string bdat = cryptoAL::random::generate_base64_random_string(KEY_SIZE / 2);
				cryptoAL::cryptodata datain;
				cryptoAL::cryptodata dataenc;
				cryptoAL::cryptodata dataout;
				datain.buffer.write(bdat.data(), bdat.size());

				// "encode_idea data file must be multiple of 8 bytes idea: "
				// "encode_idea key must be multiple of 16 bytes: "

				bool r = MSG::encode_idea(datain, bkey.data(), bkey.size(), dataenc);
				if (r) r = MSG::decode_idea(dataenc, bkey.data(), bkey.size(), dataout);
				if (r) if (dataout.buffer.size() != bdat.size()) r = false;
				if (r) if (memcmp(dataout.buffer.getdata(),bdat.data(), bdat.size())!=0) r = false;
				if (!r)
				{
					throw std::runtime_error("IDEA key encryption not working on Base64");
				}
			}

			if (USE_BASE64_RND_KEY_GENERATOR == false)
				pending_random_key = cryptoAL::random::generate_base10_random_string(KEY_SIZE);
			else
				pending_random_key = cryptoAL::random::generate_base64_random_string(KEY_SIZE);
		}

		this->set_key_hint();
		this->handleRequest();
	}

	bool ysServer::check_default_encrypt(std::string& key)
	{
		MSG m, m2, m3;
		m.make_msg(MSG_TEXT, "Hello Test", key);

		m2.make_encrypt_msg(m, key);
		m3.make_decrypt_msg(m2, key);
		return m.is_same(m3);
	}

	//
	void ysServer::set_key_hint()
	{
		// ask user...
		initial_key_hint = "1000th prime number";
		initial_key = "7919";
	}

	void ysServer::createServer() {
		const int opt = 1;
		this->createSocket();
		if (setsockopt(this->m_socketFd, SOL_SOCKET, SO_REUSEADDR, (const char*) &opt, sizeof (opt))) {
			throw std::runtime_error("setsockopt");
		}
	}

	void ysServer::bindServer()
	{
		if (bind(this->m_socketFd, reinterpret_cast<sockaddr*> (&this->m_socketInfo), this->m_addressLen) == -1)
		{
            std::string serr;
#ifdef _WIN32
#else
            int r = errno;
            serr = std::to_string(r) + " ";
            if (r == EACCES) serr = "EACCES";
            else if (r == EADDRINUSE) serr = "EADDRINUSE";
            else if (r == EADDRINUSE) serr = "EADDRINUSE";
            else if (r == EINVAL) serr = "EINVAL";
            else if (r == ENOTSOCK) serr = "ENOTSOCK";
            else if (r == EADDRNOTAVAIL) serr = "EADDRNOTAVAIL";

            else if (r == EFAULT) serr = "EFAULT";
            else if (r == ELOOP) serr = "ELOOP";
            else if (r == ENAMETOOLONG) serr = "ENAMETOOLONG";
            else if (r == ENOENT) serr = "ENOENT";
            else if (r == ENOMEM) serr = "ENOMEM";
            else if (r == ENOTDIR) serr = "ENOTDIR";
            else if (r == EROFS) serr = "ENOTEROFSDIR";

#endif
		/*
		RETURN VALUE         top

       On success, zero is returned.  On error, -1 is returned, and
       errno is set to indicate the error.

ERRORS         top

       EACCES The address is protected, and the user is not the
              superuser.

       EADDRINUSE
              The given address is already in use.

       EADDRINUSE
              (Internet domain sockets) The port number was specified as
              zero in the socket address structure, but, upon attempting
              to bind to an ephemeral port, it was determined that all
              port numbers in the ephemeral port range are currently in
              use.  See the discussion of
              /proc/sys/net/ipv4/ip_local_port_range ip(7).

       EBADF  sockfd is not a valid file descriptor.

       EINVAL The socket is already bound to an address.

       EINVAL addrlen is wrong, or addr is not a valid address for this
              socket's domain.

       ENOTSOCK
              The file descriptor sockfd does not refer to a socket.

       The following errors are specific to UNIX domain (AF_UNIX)
       sockets:

       EACCES Search permission is denied on a component of the path
              prefix.  (See also path_resolution(7).)

       EADDRNOTAVAIL
              A nonexistent interface was requested or the requested
              address was not local.

       EFAULT addr points outside the user's accessible address space.

       ELOOP  Too many symbolic links were encountered in resolving
              addr.

       ENAMETOOLONG
              addr is too long.

       ENOENT A component in the directory prefix of the socket pathname
              does not exist.

       ENOMEM Insufficient kernel memory was available.

       ENOTDIR
              A component of the path prefix is not a directory.

       EROFS  The socket inode would reside on a read-only filesystem.

		*/
			throw std::runtime_error("Could not bind socket " + serr);
		}
	}

	void ysServer::listenServer() {
		if (listen(this->m_socketFd, this->m_connectionSize) == -1) {
			throw std::runtime_error("Could not open socket for listening");
		}
	}

	void ysServer::handleRequest() {
		showMessage("ysServer is running...");
		showMessage(std::string(inet_ntoa(this->m_socketInfo.sin_addr)) + ":" + std::to_string(ntohs(this->m_socketInfo.sin_port)));

		while (1) {
			struct sockaddr_in temp_addr;
			socklen_t temp_len = sizeof (temp_addr);
			int temp_socket = accept(this->m_socketFd, reinterpret_cast<sockaddr*> (&temp_addr), &temp_len);

			// check connection limit
			if (this->m_nodeSize + 1 > this->m_connectionSize)
			{
				MSG  m;
				m.make_msg(MSG_TEXT, "Server is full.", getDEFAULT_KEY());
				sendMessageBuffer(temp_socket, m, getDEFAULT_KEY());
#ifdef _WIN32
				closesocket(temp_socket);
#else
				close(temp_socket);
#endif
				continue;
			}
			this->m_nodeSize += 1;

			// create client
			ysNodeV4 * new_client = new ysNodeV4();
			new_client->setSocketInfo(temp_addr);
			new_client->setSocketFd(temp_socket);
			new_client->setState(STATE::OPEN);

			std::string client_ip(inet_ntoa(temp_addr.sin_addr));
			std::string client_port(std::to_string(ntohs(temp_addr.sin_port)));

			// create thread
			this->v_thread.push_back(std::thread([ = ]{
				int len;
				char message_buffer[MESSAGE_SIZE+1];
				while ((len = recv(new_client->getSocketFd(), message_buffer, MESSAGE_SIZE, 0)) > 0)
				{
					size_t idx = get_client_index(new_client->getSocketFd());

					// Parse message
					MSG m;
					bool r;
					if (message_buffer[0] == MSG_CMD_RESP_KEY_HINT)
						r = m.parse(message_buffer, len, getDEFAULT_KEY());
					else if (!v_client[idx]->initial_key_validation_done)
						r = m.parse(message_buffer, len, getDEFAULT_KEY());
					else if (!v_client[idx]->random_key_validation_done)
						r = m.parse(message_buffer, len, v_client[idx]->initial_key);
					else
						r = m.parse(message_buffer, len, v_client[idx]->random_key);

					if (r == false)
					{
						//...
					}

					if (m.type_msg == MSG_CMD_RESP_KEY_HINT)
					{
						if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_KEY_HINT" << std::endl;
						if (DEBUG_INFO) std::cout.flush();

						std::string s = m.get_data_as_string();
						if (s == initial_key)
						{
							if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_KEY_VALID " << idx << std::endl;

							MSG m;
							m.make_msg(MSG_CMD_INFO_KEY_VALID, "Initial key is valid", getDEFAULT_KEY());
							sendMessageBuffer(v_client[idx]->getSocketFd(), m, getDEFAULT_KEY());

							v_client[idx]->initial_key = initial_key;
							v_client[idx]->initial_key_validation_done = true;

							if (v_client[idx]->username.size() == 0)
							{
								if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_USERNAME " << idx << std::endl;

								MSG m;
								std::string s = "Please, provide your username : ";
								m.make_msg(MSG_CMD_REQU_USERNAME, s, v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);
								sendMessageBuffer(v_client[idx]->getSocketFd(), m, v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);
							}
						}
						else
						{
							std::cout << "WARNING invalid initial_key recv " << idx << " " << s << std::endl;
						}
					}
					else if (m.type_msg == MSG_CMD_RESP_ACCEPT_RND_KEY)
					{
						if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
						if (DEBUG_INFO) std::cout.flush();

						std::string s = m.get_data_as_string(); // rnd key digest

						SHA256 sha;
						sha.update((uint8_t*)v_client[idx]->pending_random_key.data(), v_client[idx]->pending_random_key.size());
						uint8_t* digestkey = sha.digest();
						std::string str_digest = sha.toString(digestkey);
						delete[]digestkey;

						if (s == str_digest)
						{
							if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_RND_KEY_VALID " << idx << std::endl;

							MSG m;
							m.make_msg(MSG_CMD_INFO_RND_KEY_VALID, "Random key is valid",
								v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);

							sendMessageBuffer(v_client[idx]->getSocketFd(), m, v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);

							v_client[idx]->random_key = v_client[idx]->pending_random_key;

							v_client[idx]->random_key_validation_done = true;
							v_client[idx]->new_pending_random_key = false;
						}
						else
						{
							std::cout << "ERROR received invalid random_key digest" << idx << " " << s << std::endl;
						}
					}
					else if (m.type_msg == MSG_CMD_RESP_USERNAME)
					{
						if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_USERNAME" << std::endl;

						std::string user = m.get_data_as_string();
						if (user.size() == 0) user = std::to_string(idx + 1);
						v_client[idx]->username = user;
					}

					else if (m.type_msg == MSG_TEXT)
					{
						std::string username_display;
						if (v_client[idx]->username.size() > 0) username_display = " (" + v_client[idx]->username + ") ";
						std::string message(client_ip + ":" + client_port + username_display + "> " + m.get_data_as_string());

						this->sendMessageAll(message, new_client->getSocketFd());
						//this->sendMessageClients(message);


						if (!v_client[idx]->initial_key_validation_done)
						{
							this->request_client_initial_key(new_client->getSocketFd());
						}
						else if (v_client[idx]->username.size() == 0)
						{
							if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_USERNAME " << idx << std::endl;

							MSG m;
							std::string s = "Please, provide your username : ";
							m.make_msg(MSG_CMD_REQU_USERNAME, s, v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);
							sendMessageBuffer(v_client[idx]->getSocketFd(), m, v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);
						}
						else if (!v_client[idx]->random_key_validation_done)
						{
							this->request_accept_rnd_key(new_client->getSocketFd());
						}
						else if (v_client[idx]->new_pending_random_key)
						{
							std::string work = v_client[idx]->pending_random_key;

							if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << idx << std::endl;
							if (DEBUG_INFO)
								std::cout << "Random key send ["
								+ get_summary_hex((char*)work.data(), work.size())
								+ "]" << std::endl;

							SHA256 sha;
							sha.update((uint8_t*)work.data(), work.size());
							uint8_t* digestkey = sha.digest();
							std::string str_digest = sha.toString(digestkey);
							delete[]digestkey;

							if (DEBUG_INFO)
								std::cout << "Random key send digest ["
								+ str_digest
								+ "]" << std::endl;

							if (DEBUG_INFO)
							{
								CRC32 chk;
								chk.update((char*)work.data(), work.size());
								std::cout << "Random key send CRC32 ["
									<< chk.get_hash()
									<< "]" << std::endl;
							}

							if (DEBUG_INFO)
							{
								std::cout << "Random key send ["
									<< work
									<< "]" << std::endl;
							}

							MSG m;
							m.make_msg(MSG_CMD_REQU_ACCEPT_RND_KEY, v_client[idx]->pending_random_key,
								v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);

							sendMessageBuffer(v_client[idx]->getSocketFd(), m, v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);
						}
						else
						{
							if (USE_BASE64_RND_KEY_GENERATOR == false)
								v_client[idx]->pending_random_key = cryptoAL::random::generate_base10_random_string(KEY_SIZE);
							else
								v_client[idx]->pending_random_key = cryptoAL::random::generate_base64_random_string(KEY_SIZE);

							v_client[idx]->new_pending_random_key = true;
						}
					}

					std::memset(message_buffer, '\0', sizeof (message_buffer));
				}

				// connection closed.
 				this->v_client.erase(std::remove(this->v_client.begin(), this->v_client.end(), new_client));
				this->showMessage(client_ip + ":" + client_port + " disconnected.");
			}));

			this->showMessage(client_ip + ":" + client_port + " connected.");
			this->v_client.push_back(new_client);
		}
	}

	void ysServer::sendMessageClients(const std::string& t_message) {
		for (auto &client : v_client)
		{
			MSG  m;

			std::string key;
			if (!client->initial_key_validation_done)
				key = getDEFAULT_KEY();
			else if (!client->random_key_validation_done)
				key = client->initial_key;
			else
				key = client->random_key;

			m.make_msg(MSG_TEXT, t_message, key);
			sendMessageBuffer(client->getSocketFd(), m, key);
		}
	}

	void ysServer::sendMessageAll(const std::string& t_message, const int& t_socket)
	{
		for (auto &client : v_client) {
			if (client->getSocketFd() != t_socket)
			{
				std::string key;
				if (!client->initial_key_validation_done)
					key = getDEFAULT_KEY();
				else if (!client->random_key_validation_done)
					key = client->initial_key;
				else
					key = client->random_key;

				MSG m;
				m.make_msg(MSG_TEXT, t_message, key);
				sendMessageBuffer(client->getSocketFd(), m, key);

			}
		}
	}

	size_t ysServer::get_client_index(const int& t_socket)
	{
		size_t idx = 0;
		for (auto& client : v_client)
		{
			if (client->getSocketFd() == t_socket)
			{
				return idx;
			}
			idx++;
		}
		return idx;
	}

	void ysServer::request_client_initial_key(const int& t_socket)
	{
		size_t idx = get_client_index(t_socket);
		if (!v_client[idx]->initial_key_validation_done)
		{
			if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_KEY_HINT " << idx << std::endl;

			MSG m;
			std::string s = "Please, provide key, hint is " + initial_key_hint;
			m.make_msg(MSG_CMD_REQU_KEY_HINT, s, getDEFAULT_KEY());
			sendMessageBuffer(v_client[idx]->getSocketFd(), m, getDEFAULT_KEY());
		}
	}
	void ysServer::request_accept_rnd_key(const int& t_socket)
	{
		size_t idx = get_client_index(t_socket);
		if (!v_client[idx]->random_key_validation_done)
		{
			if (DEBUG_INFO) std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << idx << std::endl;
			if (DEBUG_INFO)
				std::cout << "First Random key send ["
				+ get_summary_hex((char*)pending_random_key.data(), pending_random_key.size())
				+ "]" << std::endl;

			SHA256 sha;
			sha.update((uint8_t*)pending_random_key.data(), pending_random_key.size());
			uint8_t* digestkey = sha.digest();
			std::string str_digest = sha.toString(digestkey);
			delete[]digestkey;

			if (DEBUG_INFO)
				std::cout << "First Random key send digest ["
					+ str_digest
					+ "]" << std::endl;

			MSG m;
			v_client[idx]->pending_random_key = pending_random_key;

			m.make_msg(MSG_CMD_REQU_ACCEPT_RND_KEY, v_client[idx]->pending_random_key,
				v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);

			sendMessageBuffer(v_client[idx]->getSocketFd(), m, v_client[idx]->random_key_validation_done ? v_client[idx]->random_key : v_client[idx]->initial_key);
		}
	}

	void ysServer::closeClient() {
		for (auto &client : v_client) {
			delete client;
		}
	}

	void ysServer::joinThread() {
		for (auto &thread : v_thread) {
			if (thread.joinable()) {
				thread.join();
			}
		}
	}

	void ysServer::closeServer() {
		sendMessageClients("Server closed.");
		this->closeClient();
		this->closeSocket();
		this->joinThread();
		this->v_client.clear();
		this->v_thread.clear();
	}

	ysServer::~ysServer() {
		this->closeServer();
	}

}
