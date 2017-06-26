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
#ifndef UTILS_STRINGHELPER_H
#define UTILS_STRINGHELPER_H

#include <string>
#include <vector>
#include <time.h>
#include <tins/dot11.h>

using std::string;
using std::vector;
using Tins::Dot11;

namespace wifibeat
{
	namespace utils
	{
		class stringHelper {
			public:
				static string mac2str(Dot11::address_type mac);
				static vector<string> split(const string & toSplit, char by, bool doTrim = true);
				static void to_upper(std::string & str);
				static void to_lower(std::string & str);
				static void ltrim(std::string &s);
				static void rtrim(std::string &s);
				static void trim(std::string &s);
				static string timespec2RFC3339string(struct timespec & ts);
				char * hex2string(const uint8_t * data, unsigned int length, unsigned int offset, unsigned int howMany, bool useSeparator = true, char separator = '-');
		};
	}
}

#endif // UTILS_STRINGHELPER_H