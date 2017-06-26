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
#ifndef UTILS_WIFI_H
#define UTILS_WIFI_H

#include <string>
#include <vector>

using std::vector;
using std::string;

namespace wifibeat
{
	namespace utils
	{
		class wifi {
			public:
				static int channel2frequency(const unsigned int chan);
				static bool isInterfaceValid(const string & iface, const vector<string> & ifaces = vector<string>());
				static vector <string> interfaces();
				static bool setInterfaceUp(const string & iface);
		};
	}
}

#endif // UTILS_WIFI_H