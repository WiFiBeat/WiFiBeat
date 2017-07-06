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
#include "filewriting.h"
#include "utils/logger.h"
#include "utils/Locker.h"
#include <sstream>
#include <time.h>

using std::stringstream;

wifibeat::threads::filewriting::filewriting(const string & interface, const string & filePrefix) 
	: _string(""), _interface(interface), _filePrefix(filePrefix), _packet_writer(NULL)
{
	this->Name("File Writing");
	if (pthread_mutex_init(&this->_mutex, NULL) != 0) {
		LOG_CRITICAL("Failed initializing Filewriter mutex");
		throw string("Failed initializing Filewriter mutex");
    }
	this->_mutexInit = true;
}

wifibeat::threads::filewriting::~filewriting()
{
	if (this->_mutexInit) {
		wifibeat::utils::Locker * l = new wifibeat::utils::Locker(&this->_mutex);
		delete this->_packet_writer;
		delete l;
		pthread_mutex_destroy(&this->_mutex);
	} else {
		delete this->_packet_writer;
	}
}

bool wifibeat::threads::filewriting::init_function()
{
	if (this->_interface.empty() || this->_filePrefix.empty()) {
		return false;
	}

	// Generate filename
	time_t ltime;
	ltime = time(&ltime);
	struct tm time_now;
	localtime_r(&ltime, &time_now);

	stringstream ss;
	ss << this->_filePrefix << '-'
		<< this->_interface << '_'
		<< (time_now.tm_year + 1900) << '-'
		<< (time_now.tm_mon + 1) << '-'
		<< time_now.tm_mday << '_'
		<< time_now.tm_hour << '.'
		<< time_now.tm_min << '.'
		<< time_now.tm_sec
		<< ".pcap";
	this->_filename = ss.str();

	wifibeat::utils::Locker l(&this->_mutex);
	try {
		this->_packet_writer = new PacketWriter(this->_filename, Tins::DataLinkType<Tins::RadioTap>());
	} catch (...) {
		LOG_ERROR("Failed creating output PCAP file <" + this->_filename + ">");
		return false;
	}

	return true;
}

void wifibeat::threads::filewriting::recurring()
{
	// 1. Get all packets from the input queue
	std::queue<PacketTimestamp *> items = this->getAllItemsFromInputQueue();

	while (!items.empty()) {
		PacketTimestamp *item = items.front();
		items.pop();
		if (item == NULL) {
			continue;
		}

		// 2. Write to file
		wifibeat::utils::Locker l(&this->_mutex);
		if (this->_packet_writer != NULL) {
			this->_packet_writer->write(*(item->getPDU()));
		}

		// 3. Put the decrypted packet in the queue
		this->sendToNextThreadsQueue(item);
	}
}

string wifibeat::threads::filewriting::toString()
{
	if (this->_interface.empty()) {
		return "";
	}

	if (this->_string.empty()) {
		if (this->_filename.empty()) {
			stringstream ss;
			ss << this->Name() << " <" << this->_interface << '>';
			return ss.str();
		} else {
			stringstream ss;
			ss << this->Name() << " <" << this->_filename << '>';
			this->_string = ss.str();
		}
	}

	return this->_string;
}

string wifibeat::threads::filewriting::Interface()
{
	return this->_interface;
}
