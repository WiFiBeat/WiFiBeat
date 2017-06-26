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
#include "file.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ostream>
#include <fstream>

bool wifibeat::utils::file::exists(const string & path) {
	if (path.empty()) {
		return false;
	}
	
	struct stat buffer;
	return stat (path.c_str(), &buffer) == 0;
}

bool wifibeat::utils::file::writePID(const string & path)
{
	if (path.empty()) {
		return false;
	}

	try {
		std::ofstream fs(path);
		fs << ::getpid();
		fs.flush();
		fs.close();
	} catch (...) {
		return false;
	}

	return true;
}

bool wifibeat::utils::file::rm(const std::string & path) {
	if (!exists(path)) {
		return false;
	}
	
	return remove(path.c_str()) == 0;
}