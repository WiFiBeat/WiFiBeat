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
#ifndef UTILS_TINS_H
#define UTILS_TINS_H

#include <tins/pdu.h>
#include <tins/dot11.h>
#include <tins/radiotap.h>
#include <tins/dot11/dot11_base.h>
#include <tins/dot11/dot11_control.h>
#include <tins/dot11/dot11_mgmt.h>
#include <tins/dot11/dot11_data.h>
#include <tins/rsn_information.h>
#include <simplejson-cpp/simplejson.h>
#include <string>
#include "PacketTimestamp.h"

using Tins::RadioTap;
using Tins::Dot11;
using Tins::Dot11ManagementFrame;
using Tins::Dot11Control;
using Tins::Dot11Data;
using Tins::PDU;
using Tins::RSNInformation;
using std::string;
using simplejson::JSONObject;

#define IEEE80211_MANAGEMENT_FRAME 0
#define IEEE80211_CONTROL_FRAME 1
#define IEEE80211_DATA_FRAME 2


#define MGT_FRAME_ASSOC_REQUEST 0
#define MGT_FRAME_ASSOC_RESPONSE 1
#define MGT_FRAME_PROBE_RESPONSE 5
#define MGT_FRAME_BEACON 8
#define MGT_FRAME_AUTHENTICATION 11
#define MGT_FRAME_DEAUTHENTICATION 12

#define IE_ESSID 0
#define IE_SUPPORTED_RATES 1
#define IE_DS_PARAM_SET 3
#define IE_TIM 5
#define IE_COUNTRY_INFO 7
#define IE_QBSS_LOAD_ELEMENT 11
#define IE_POWER_CONSTRAINT 32
#define IE_ERP_INFO42 42
#define IE_ERP_INFO47 47
#define IE_HT_CAPA_D110 45
#define IE_RSN_INFORMATION 48
#define IE_EXT_SUPPORTED_RATES 50
#define IE_AP_CHANNEL_REPORT 51
#define IE_NEIGHBOR_REPORT 52
#define IE_MOBILITY_DOMAIN 54
#define IE_HT_INFO_D110 61
#define IE_EXTENDED_CAPA 127
#define IE_UPID 171
#define IE_VENDOR 221

namespace wifibeat
{
	namespace utils
	{
		class tins {
			private:


				static JSONObject * radiotap2String(const RadioTap * header);
				static JSONObject * Dot11ToString(const Dot11 * frame);
				static JSONObject * Dot11Management2String(const Dot11ManagementFrame * frame);
				static JSONObject * Dot11Control2String(const Dot11Control * frame);

				// Data
				struct Dot11DataObjects {
					JSONObject * QoS;
					JSONObject * wep;
					JSONObject * tkip;
					JSONObject * ccmp;
					JSONObject * data;
					Dot11DataObjects() : QoS(NULL), wep(NULL), tkip(NULL), ccmp(NULL), data(NULL) { }
				};
				static Dot11DataObjects * Dot11Data2String(const Dot11Data * frame);

				static JSONObject * ParseMCSSet(const uint8_t* data_ptr, unsigned int len, unsigned int offset);
				static JSONObject * ParseCapabilities(Tins::Dot11ManagementFrame::capability_information & ci);
				static bool ParseDot11ManagementOptions(const Tins::Dot11::options_type & mgtOptions, JSONObject * wlan_mgt, const Dot11ManagementFrame * frame);
				static JSONObject * ParseRSNInformationCipherSuite(RSNInformation::CypherSuites suite);

		public:
				static JSONObject * PacketTimestamp2String(const PacketTimestamp * frame);
		};
	}
}

#endif // UTILS_TINS_H