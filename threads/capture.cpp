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
#include "capture.h"
#include "utils/wifi.h"
#include "utils/logger.h"
#include <exception>
#include <sstream>

using std::stringstream;
using std::exception;

wifibeat::threads::capture::capture(const string & interface, const string & filter)
	: _interface(interface), _filter(filter), _sniffer(NULL), _pcapFd(-1), _string("")
{
	this->Name("capture");
}

wifibeat::threads::capture::~capture()
{
	delete this->_sniffer;
}

void wifibeat::threads::capture::recurring()
{
	// Initialize structures
	FD_ZERO(&(this->_fdSet));
	FD_SET(this->_pcapFd, &(this->_fdSet));
	this->_tv.tv_sec = 0;
	this->_tv.tv_usec = 1;

	// Check if there is data to read
	if (select (FD_SETSIZE, &this->_fdSet, NULL, NULL, &this->_tv) < 1) {
		return;
	}

	// Get packet
	//Tins::PtrPacket packet();
	Tins::PDU * packet = this->_sniffer->next_packet();
	PacketTimestamp * pts = new PacketTimestamp(packet);
	this->sendToNextThreadsQueue(pts);
}

bool wifibeat::threads::capture::init_function()
{
	if (this->_sniffer) {
		return true;
	}
	if (this->_interface.empty()) {
		LOG_ERROR("Interface is empty");
		return false;
	}

	stringstream ss;
	if (!wifibeat::utils::wifi::isInterfaceValid(this->_interface)) {
		ss << "Interface <" << this->_interface << "> is invalid";
		LOG_ERROR(ss.str());
		return false;
	}

	// Make sure interface is up
	if (!wifibeat::utils::wifi::setInterfaceUp(this->_interface)) {
		ss << "Failed to put <" << this->_interface << "> up.";
		LOG_ERROR(ss.str());
		return false;
	}

	// Configure sniffer
	Tins::SnifferConfiguration snifferConfig;
	// https://github.com/mfontanini/libtins/issues/41
	//snifferConfig.set_timeout(1);
	snifferConfig.set_immediate_mode(true);

	// Add filter
	if (!this->_filter.empty()) {
		LOG_NOTICE("Added filter <" + this->_filter + "> to interface <" + this->_interface + ">");
		snifferConfig.set_filter(this->_filter);
	}

	try {
		// Start capture
		this->_sniffer = new Tins::Sniffer(this->_interface, snifferConfig);
	} catch (const exception & e) {
		ss << "Failed initializing capture on " << this->_interface << ": " << e.what();
		LOG_CRITICAL(ss.str());
		return false;
	}

	LOG_NOTICE("Created sniffer on <" + this->_interface + ">");

	// Raw PDUs => Parsed in a different thread.
	//this->_sniffer->set_extract_raw_pdus(true); 

	try {
		// Get handle so we can use select to know if there is a packet available
		pcap_t * pcap_handle = this->_sniffer->get_pcap_handle();
		this->_pcapFd = pcap_get_selectable_fd(pcap_handle);
	} catch (const exception & e) {
		ss << "Failed obtaining PCAP handle on sniffer for " << this->_interface << ": " << e.what();
		LOG_CRITICAL(ss.str());
		return false;
	}

	// Make sure we're getting wifi frames
	int linktype = this->_sniffer->link_type();
	if (linktype != DLT_IEEE802_11_RADIO && linktype != DLT_IEEE802_11) {
		ss << "Invalid link type: " << this->_sniffer->link_type();
		LOG_CRITICAL(ss.str());
		delete this->_sniffer;
		this->_sniffer = NULL;
		return false;
	}

	LOG_NOTICE("Link type on <" + this->_interface + ">: " + std::to_string(linktype));

	return true;
}

string wifibeat::threads::capture::toString()
{
	if (this->_interface.empty()) {
		return "";
	}

	if (this->_string.empty()) {
		std::stringstream ss;
		ss << "Interface <" << this->_interface << '>';

		if (!this->_filter.empty()) {
			ss << " - Filter <" << this->_filter << '>';
		}

		this->_string = ss.str();
	}

	return this->_string;
}

string wifibeat::threads::capture::Interface()
{
	return this->_interface;
}
