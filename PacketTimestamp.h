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
#ifndef PACKETTIMESTAMP_H
#define PACKETTIMESTAMP_H

#include <tins/pdu.h>
#include <tins/packet.h>

using Tins::PDU;
using Tins::PtrPacket;

namespace wifibeat {
	class PacketTimestamp
	{
		private:
			// PDUs
			PDU * _pdu;
			//PtrPacket _rawPacket;

			// Time stuff
			struct timespec _ts;
			void setTime();

		public:
			//PacketTimestamp(const PtrPacket & packet);
			PacketTimestamp(const PacketTimestamp & pts);
			PacketTimestamp(PDU * pdu);
			~PacketTimestamp();

			// Time related
			struct timespec getTimespec() const;
			unsigned long long int nsSinceEpoch();

			PDU * getPDU() const;
	};
};

#endif // PACKETTIMESTAMP_H
