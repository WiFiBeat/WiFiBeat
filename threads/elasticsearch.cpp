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
#include "elasticsearch.h"
#include "utils/logger.h"
#include "utils/tins.h"
#include "utils/Locker.h"
#include "utils/beat.h"
#include "utils/stringHelper.h"
#include <sstream>
#include <rapidjson/document.h>

using namespace rapidjson;

wifibeat::threads::elasticsearch::elasticsearch(const ElasticSearchConnection & connection)
	: _settings(connection), _mutexInit(false)
{
	this->Name("elasticsearch");

	// Initialize mutex
	if (pthread_mutex_init(&this->_connectionMutex, NULL) != 0) {
		LOG_CRITICAL("Failed initializing elasticsearch connections mutex");
		throw string("Failed initializing elasticsearch connections mutex");
	}
	this->_mutexInit = true;
}

wifibeat::threads::elasticsearch::~elasticsearch()
{
	if (this->_mutexInit) {
		utils::Locker * l = new utils::Locker(&this->_connectionMutex);
		for (elastic * conn : this->_connections) {
			delete conn;
		}
		delete l;
		pthread_mutex_destroy(&this->_connectionMutex);
	} else {
		for (elastic * conn : this->_connections) {
			delete conn;
		}
	}
}

void wifibeat::threads::elasticsearch::recurring()
{
	queue<PacketTimestamp *> items = this->getAllItemsFromInputQueue();

	if (items.empty()) {
		return;
	}

	// If it is disabled, just drop all items
	if (!this->_settings.enabled) {
		while (!items.empty()) {
			PacketTimestamp * item = items.front();
			items.pop();
			delete item;
		}
	}

	// Parse and and add documents to vector
	vector <string> documents;
	while (!items.empty()) {
		PacketTimestamp * item = items.front();
		items.pop();

		// Generate document from frame
		Document d;
		JSONObject * json = wifibeat::utils::tins::PacketTimestamp2String(item);
		delete item;
		if (!json) {
			LOG_ERROR("Failed parsing 802.11 packet");
			continue;
		}

		// Add the beat field then add document to vector.
		if (wifibeat::utils::beat::Instance()->addBeatToDocument(json) == false) {
			LOG_ERROR("Failed adding Beat to JSON");
			delete json;
			continue;
		}
		string temp = json->toString();
		documents.push_back(temp);
	}
	
	// Now insert all documents
	if (documents.empty()) {
		return;
	}

	vector <string> temp;
	unsigned int amountElt;
	utils::Locker l(&this->_connectionMutex);
	

	while (documents.size() > 0) {
		// Calculate amount of elements per bulk request
		amountElt = documents.size();
		if (amountElt > this->_settings.bulkMaxSize) {
			amountElt = this->_settings.bulkMaxSize;
		}
		
		// Move elements from one vector to another
		auto it = std::next(documents.begin(), amountElt);
		temp.clear();
		std::move(documents.begin(), it, std::back_inserter(temp));
		documents.erase(documents.begin(), it);

		// Do the request
		// XXX: Make sure this behavior is the same as packetbeat:
		//      connect to first host that responds and send document
		for (elastic * conn: this->_connections) {
			beat::protocols::BulkResponse * response = conn->bulkRequest(temp, _WIFIBEAT_ES_INDEX_BASENAME);

			// Handle errors
			if (response->errors || response->httpStatus != 200) {
				stringstream ss;
				ss << "Failed inserting " << temp.size() << " documents in <" << conn->toString() << 
					">: HTTP error " << response->httpStatus;
				LOG_ERROR(ss.str());
			} else {
				stringstream ss;
				ss << "Inserted " << temp.size() << " documents in <" << conn->toString() << ">";
				LOG_DEBUG(ss.str());
				delete response;
				break;
			}
			delete response;
		}
	}
}

bool wifibeat::threads::elasticsearch::init_function()
{
	// TODO: allow keeping invalid connection and retry from time to time
	for (IPPort ipp: this->_settings.hosts) {
		string host = "://" + ipp.host + ":" + std::to_string(ipp.port);
		if (this->_settings.protocol == HTTP) {
			host = "http" + host;
		} else {
			host = "https" + host;
		}
		try {
			elastic * conn = new elastic(host);
			LOG_DEBUG("Connection successful to <" + host + ">");
			LOG_NOTICE(host + " version: " + conn->Version());
			this->_connections.push_back(conn);
		} catch (const string & ex) {
			LOG_ERROR("Failed connecting to <" + host + ">: " + ex);
		} catch (const std::exception & e) {
			LOG_ERROR("Failed connecting to <" + host + ">: " + e.what());
		}
	}

	if (this->_settings.enabled == false) {
		LOG_WARN("Elasticsearch connection disabled, dropping all frames!");
	}

	if (this->_connections.empty()) {
		LOG_CRITICAL("Not a single valid Elasticsearch host!");
		return false;
	}

	return true;
}

string wifibeat::threads::elasticsearch::toString()
{
	std::stringstream ss;

	ss << this->Name() << ": ";

	bool first = true;
	for (const IPPort & ip2: this->_settings.hosts) {
		if (first) {
			first = false;
		} else {
			ss << ", ";
		}
		ss << ip2.host << ':' << ip2.port;
	}
	ss << "] ";

	// User/pass
	if (!this->_settings.username.empty()) {
		ss << "with username <" << this->_settings.username 
			<< "> password: <" << this->_settings.password << "> ";
	}

	// Enabled/disabled
	ss << '(' << ((this->_settings.enabled) ? "En" : "Dis") << "abled)";

	return ss.str();
}