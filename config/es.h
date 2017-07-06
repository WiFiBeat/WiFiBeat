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
#ifndef CONFIG_ES_H
#define CONFIG_ES_H

#include <string>
#include <map>
#include <vector>
#include <chrono>
#include "outputBase.h"

using std::string;
using std::map;
using std::vector;

enum ESProtocol {
	HTTP,
	HTTPS
};

struct ESTemplateVersion {
	bool enabled; // true
	string path;
	ESTemplateVersion(): enabled(true), path("") { }
};

struct ElasticSearchConnection : outputBeatBase{
	ESProtocol protocol; // HTTP
	string username;
	string password;
	map <string, string> parameters;
	string pipeline;
	map <string, string> headers;
	string HTTPPath;
	string proxyURL;
	unsigned int maxRetries; // 3
	unsigned int bulkMaxSize; // 50
	unsigned int timeout; // 90
	std::chrono::seconds flushInterval; // 1 sec
	ESTemplateVersion version2x;
	ESTemplateVersion version6x;
	ElasticSearchConnection() : protocol(HTTP), username(""), password(""), pipeline(""), HTTPPath(""),
								proxyURL(""), maxRetries(3), bulkMaxSize(50), timeout(90),
								flushInterval(std::chrono::seconds(1)) { }
};

#endif // CONFIG_ES_H
