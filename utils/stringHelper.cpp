/*
 *    WiFiBeat - Parse 802.11 frames and store them in ElasticSearch
 *    Copyright (C) 2017 Thomas d'Otreppe de Bouvette 
 *                       <tdotreppe@aircrack-ng.org>
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "stringHelper.h"
#include "logger.h"
#include <algorithm>
#include <cctype>
#include <locale>
#include <sstream>
#include <string.h>

char * wifibeat::utils::stringHelper::hex2string(const uint8_t * data, unsigned int length, unsigned int offset, unsigned int howMany, bool useSeparator, char separator)
{
	if (length == 0 || length < offset + howMany ) {
		return NULL;
	}

	char * ret = NULL;
	if (useSeparator) {
		// Separator
		ret = static_cast<char*>(calloc(1, howMany * 3));
		for (unsigned int i = 0; i < howMany; ++i) {
			snprintf(ret + (i *3), 2, "%02x", data[i + offset]);
			ret[(i * 3) + 2] = separator;
		}
		ret[(howMany * 3) - 1] = 0;
	} else {
		// No separator
		ret = static_cast<char*>(calloc(1, (howMany * 2) + 1));
		for (unsigned int i = 0; i < howMany; ++i) {
			snprintf(ret + (i * 2), 2, "%02x", data[i + offset]);
		}
	}

	return ret;
}

string wifibeat::utils::stringHelper::mac2str(Dot11::address_type mac)
{
	std::stringstream ss;
	ss << mac;
	return ss.str();
}

vector<string> wifibeat::utils::stringHelper::split(const string & toSplit, char by, bool doTrim)
{
	vector<std::string> ret;
	if (toSplit.empty() || strchr(toSplit.c_str(), by) == NULL) {
		return ret;
	}

	std::stringstream ss;
	ss << toSplit;
	string to;
	while (std::getline(ss, to, by)) {
		if (doTrim) {
			wifibeat::utils::stringHelper::trim(to);
		}
		ret.push_back(to);
	}

	return ret;
}


void wifibeat::utils::stringHelper::to_upper(std::string & str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}

void wifibeat::utils::stringHelper::to_lower(std::string & str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

// ltrim, rtrim and trim come from https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring

// trim from start (in place)
inline void wifibeat::utils::stringHelper::ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}


// trim from end (in place)
inline void wifibeat::utils::stringHelper::rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
inline void wifibeat::utils::stringHelper::trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

string wifibeat::utils::stringHelper::timespec2RFC3339string(struct timespec & ts)
{
	#define T2S_BUFFER_LEN 128
	char * buf = new char[T2S_BUFFER_LEN]{0}; // Should be enough
	struct tm gm = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	stringstream ss;

	if (gmtime_r(&ts.tv_sec, &gm) == NULL) {
		ss << "Failed obtaining GMTTime for timespec: " << ts.tv_sec << " (sec) - nsec: " << ts.tv_nsec;
		LOG_ERROR(ss.str());
		delete []buf;
		throw ss.str();
	}

	ssize_t written = (ssize_t)strftime(buf, T2S_BUFFER_LEN, "%Y-%m-%dT%H:%M:%S", &gm);
	if (written <= 0) {
		ss << "Failed converting timespec to string: " << ts.tv_sec << " (sec) - nsec: " << ts.tv_nsec;
		LOG_ERROR(ss.str());
		delete []buf;
		throw ss.str();
	}
	if ((size_t)written < T2S_BUFFER_LEN) {
		snprintf(buf + written, T2S_BUFFER_LEN - (size_t)written, ".%03dZ", (int)(ts.tv_nsec/1000000));
	}
	
	string ret(buf);
	delete[] buf;
	return ret;
}