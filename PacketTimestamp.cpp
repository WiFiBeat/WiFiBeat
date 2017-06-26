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
#include "PacketTimestamp.h"
#include "utils/logger.h"
#include <exception>
#include <string>

using std::string;

wifibeat::PacketTimestamp::PacketTimestamp(const PacketTimestamp & pts) : _pdu(NULL), _ts(pts._ts)
{
	this->_pdu = pts._pdu->clone();
}

wifibeat::PacketTimestamp::PacketTimestamp(PDU * pdu) : _pdu(pdu), _ts({0,0})
{
	if (clock_gettime(CLOCK_REALTIME, &(this->_ts)) == -1) {
		stringstream ss;
		ss << "Failed to get timespec for packet <" << pdu << '>';
		LOG_ERROR(ss.str());
		throw string(ss.str());
	}
}

wifibeat::PacketTimestamp::~PacketTimestamp()
{
	delete this->_pdu;
}

//inline unsigned long long int wifibeat::PacketTimestamp::nsSinceEpoch()
//{
//	return (this->_ts.tv_sec * 1000000000ULL) + this->_ts.tv_nsec;
//}

struct timespec wifibeat::PacketTimestamp::getTimespec() const
{
	return this->_ts;
}

PDU * wifibeat::PacketTimestamp::getPDU() const
{
	/*
	if (this->_pdu == NULL) {
		this->_pdu = this->_rawPacket.pdu();
		this->_rawPacket.release_pdu();
	}
	*/
	return this->_pdu;
}