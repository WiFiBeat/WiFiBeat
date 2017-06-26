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
#include "beat.h"
#include "version.h"
#include "stringHelper.h"
#include "logger.h"
#include <unistd.h>
#include <cstdlib> // NULL
#include <sstream>

wifibeat::utils::beat* wifibeat::utils::beat::ms_instance = NULL;

wifibeat::utils::beat::beat() : _hostname("")
{
	// Obtain hostname
	char * hostname = (char *)calloc(1, HOST_NAME_MAX + 1);
	if (!hostname) {
		LOG_ERROR("Failed allocating memory for hostname");
		throw string("Failed allocating memory for hostname");
	}
	if (0 != gethostname(hostname, HOST_NAME_MAX + 1)) {
		LOG_ERROR("Failed getting hostname, " + std::to_string(HOST_NAME_MAX) + " chars is not long enough!");
		throw string("Failed getting hostname, " + std::to_string(HOST_NAME_MAX) + " chars is not long enough!");
	}

	this->_hostname = string(hostname);
}

wifibeat::utils::beat::~beat()
{
}

wifibeat::utils::beat* wifibeat::utils::beat::Instance()
{
	if (ms_instance == NULL) {
		ms_instance = new wifibeat::utils::beat();
	}
	return ms_instance;
}

void wifibeat::utils::beat::Release()
{
	if (ms_instance) {
		delete ms_instance;
	}
	ms_instance = NULL;
}

bool wifibeat::utils::beat::addBeatToDocument(JSONObject * doc)
{
	if (doc == NULL || this->_hostname.empty()) {
		return false;
	}

	// Add beat JSON to document
	JSONObject * beat = new JSONObject();
	beat->Add("hostname", this->_hostname);
	beat->Add("name", this->_hostname);
	beat->Add("version", string(VERSION_STRING));
	doc->Add("beat", beat);

	return true;
}