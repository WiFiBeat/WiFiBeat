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
#include "filereading.h"
#include "utils/file.h"
#include "utils/logger.h"
#include <exception>

wifibeat::threads::filereading::filereading(const string & file, const string & filter)
	: _file(file), _filter(filter), _sniffer(NULL), _string("")
{
	this->Name("filereading");
}

wifibeat::threads::filereading::~filereading()
{
	delete this->_sniffer;
}

void wifibeat::threads::filereading::recurring()
{
	// Get packet
	//Tins::PtrPacket packet();
	Tins::PDU * packet = this->_sniffer->next_packet();
	if (packet == NULL) {
		// EOF: https://github.com/mfontanini/libtins/issues/95#issuecomment-130759119
		this->ThreadFinished();
		LOG_NOTICE("Finished reading <" + this->_file + ">");
		return;
	}
	PacketTimestamp * pts = new PacketTimestamp(packet);
	this->sendToNextThreadsQueue(pts);
}

bool wifibeat::threads::filereading::init_function()
{
	stringstream ss;
	if (this->_sniffer) {
		return true;
	}
	if (!wifibeat::utils::file::exists(this->_file)) {
		ss << "File <" << this->_file << "> does not exists.";
		LOG_ERROR(ss.str());
		return false;
	}

	try {
		this->_sniffer = new Tins::FileSniffer(this->_file);
	} catch (const std::exception & e) {
		ss << "Failed opening file <" << this->_file << '>';
		LOG_ERROR(ss.str());
		return false;
	}

	LOG_NOTICE("Created file reader for <" + this->_file + ">");

	// Make sure we're getting wifi frames
	int linktype = this->_sniffer->link_type();
	if (linktype != DLT_IEEE802_11_RADIO && linktype != DLT_IEEE802_11) {
		ss << "Invalid link type: " << this->_sniffer->link_type();
		LOG_ERROR(ss.str());
		delete this->_sniffer;
		this->_sniffer = NULL;
		return false;
	}

	LOG_NOTICE("Link type for <" + this->_file + ">: " + std::to_string(linktype));

	return true;
}

string wifibeat::threads::filereading::toString()
{
	if (this->_file.empty()) {
		return "";
	}

	if (this->_string.empty()) {
		std::stringstream ss;
		ss << "File <" << this->_file << '>';
		
		if (!this->_filter.empty()) {
			ss << " - Filter <" << this->_filter << '>';
		}

		this->_string = ss.str();
	}

	return this->_string;
}