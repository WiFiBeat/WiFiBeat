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
#ifndef UTILS_BEAT_H
#define UTILS_BEAT_H

#include <string>
#include <simplejson-cpp/simplejson.h>

using std::string;
using simplejson::JSONObject;

namespace wifibeat
{
	namespace utils
	{
		class beat
		{
			static beat* ms_instance;

			public:
				static beat* Instance();
				static void Release();
				bool addBeatToDocument(JSONObject * doc);

			private:
				beat();
				~beat();
				string _hostname;

		};
	}
}

#endif // UTILS_BEAT_H
