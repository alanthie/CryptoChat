#pragma once
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include "string_util.hpp"
#include "file_util.hpp"
#include "vigenere.hpp"


namespace NETW_MSG
{
	static bool challenge_answer(const std::string& filename, std::string& out_answer, std::string& out_error)
	{
		bool r = false;
		if (file_util::fileexists(filename))
		{
			cryptoAL::cryptodata file;
			if (file.read_from_file(filename))
			{
				std::string work = std::string(file.buffer.getdata(), file.buffer.size());
				std::erase(work, '\r');
				std::erase(work, '\n');

				SHA256 sha;
				sha.update((uint8_t*)work.data(), work.size());
				uint8_t* digestkey = sha.digest();
				std::string str_digest = sha.toString(digestkey);
				delete[]digestkey;

				out_answer = str_digest;
				r = true;
			}
			else
			{
				std::stringstream ss; ss << "ERROR - can not read file: " << filename << std::endl;
				out_error = ss.str();
			}
		}
		else
		{
			std::stringstream ss; ss << "ERROR - no file: " << filename << std::endl;
			out_error = ss.str();
		}
		return r;
	}

	static bool challenge_read_from_file(const std::string& filename, std::map<std::string, std::string>& map_out, std::string& out_error)
	{
		// Example of challenge file
		//C----------------------------------------------------------------------------
		//CChallenge Description
		//CSave the link content in a file
		//CLink : https://drive.google.com/file/d/1YfyMe7I5aiQYplDCzdjx8BWUJlOrw_4z/view
		//C----------------------------------------------------------------------------
		//FEnter the filename you saved
		//A.....
		// 
		//C----------------------------------------------------------------------------
		//CChallenge Description
		//CPrime numbers = 2, 3, 5, 7, 11, ...
		//C----------------------------------------------------------------------------
		//FEnter the 1000th prime number
		//A7919

		bool r = true;
		if (file_util::fileexists(filename))
		{
			cryptoAL::cryptodata file;
			if (file.read_from_file(filename))
			{
				std::string work = std::string(file.buffer.getdata(), file.buffer.size());
				std::erase(work, '\r');

				std::vector<std::string> lines = NETW_MSG::split(work, "\n");
				std::string text;
				for (size_t i = 0; i < lines.size(); i++)
				{
					if (lines[i][0] == 'C')
					{
						text.append(lines[i]); text.append("\n");
					}
					else if (lines[i][0] == 'F')
					{
						text.append(lines[i]); text.append("\n");
					}
					else if (lines[i][0] == 'T')
					{
						text.append(lines[i]); text.append("\n");
					}
					else if (lines[i][0] == 'A')
					{
						if (cryptoAL_vigenere::is_string_ok(lines[i]) == true)
			            {
			                // cryptoAL_vigenere::AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
							map_out[text] = lines[i].substr(1, lines[i].size() - 1);
							text.clear();
			            }
			            else
			            {
							std::stringstream ss; ss << "ERROR - Invalid char in answer, use " << cryptoAL_vigenere::AVAILABLE_CHARS << std::endl;
							out_error = ss.str();
							r = false;
							break;
			            }
					}
				}
			}
			else
			{
				std::stringstream ss; ss << "ERROR - can not read file: " << filename << std::endl;
				out_error = ss.str();
				r = false;
			}
		}
		else
		{
			std::stringstream ss; ss << "ERROR - no file: " << filename << std::endl;
			out_error = ss.str();
			r = false;
		}
		return r;
	}
}