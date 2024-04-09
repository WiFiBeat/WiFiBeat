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
// TODO: Look at wireshark repo: wireshark/epan/dissectors/packet-ieee80211.c
#include "tins.h"
#include "stringHelper.h"
#include "logger.h"
#include <sstream>
#include <list>
#include <bitset>
#include <tins/dot11/dot11_beacon.h>
#include <tins/dot11/dot11_data.h>
#include <tins/dot11/dot11_control.h>
#include <tins/dot11/dot11_assoc.h>
#include <tins/dot11/dot11_auth.h>
#include <tins/dot11/dot11_probe.h>
#include <stdio.h>

using Tins::Dot11Deauthentication;
using Tins::Dot11ProbeResponse;
using Tins::Dot11Authentication;
using Tins::Dot11AssocRequest;
using Tins::Dot11AssocResponse;
using Tins::Dot11Beacon;
using Tins::Dot11QoSData;
using Tins::Dot11ControlTA;
using std::list;
using std::bitset;

JSONObject * wifibeat::utils::tins::PacketTimestamp2String(const PacketTimestamp * frame)
{
	if (frame == NULL) {
		LOG_WARN("NULL frame, I can't parse that!");
		return NULL;
	}

	// Prepare document
	JSONObject * doc = new JSONObject();

	// Add @timestamp
	// TODO: Verify timestamp is good
	struct timespec ts = frame->getTimespec();
	doc->Add("@timestamp", stringHelper::timespec2RFC3339string(ts));


	// Get PDU to parse the frame
	const PDU * pdu = frame->getPDU();

	// Parse radiotap header
	const RadioTap * radiotapHeader = pdu->find_pdu<RadioTap>();
	JSONObject * radiotapDoc = NULL;
	if (radiotapHeader == NULL) {
		LOG_ERROR("Unsupported frame/header type");
		delete doc;
		return NULL;
	}

	radiotapDoc = radiotap2String(radiotapHeader);
	if (radiotapDoc == NULL) {
		LOG_ERROR("Failed parsing radiotap header!");
		delete doc;
		return NULL;
	} else {
		doc->Add("radiotap", radiotapDoc);
	}

	// Parse WLAN frame
	const Dot11 * wlanFrame = pdu->find_pdu<Dot11>();
	if (wlanFrame == NULL) {
		LOG_ERROR("Not a 802.11 frame!");
		delete doc;
		return NULL;
	}

	JSONObject * wlanDoc = Dot11ToString(wlanFrame);
	if (wlanDoc == NULL) {
		LOG_ERROR("Failed to parse 802.11 packet. Report it along with the capture file or specific packet.");
		delete doc;
		return NULL;
	} else {
		doc->Add("wlan", wlanDoc);
	}

	// Management/Control/Data
	switch (wlanFrame->type()) {
		case IEEE80211_MANAGEMENT_FRAME: // Management
			{
				const Dot11ManagementFrame * mgmt = pdu->find_pdu<Dot11ManagementFrame>();
				if (mgmt) {
					JSONObject * wlan_mgt = Dot11Management2String(mgmt);
					if (wlan_mgt == NULL) {
						LOG_ERROR("Failed to parsing management frame!");
						delete doc;
						return NULL;
					}
					doc->Add("wlan_mgt", wlan_mgt);
				}
			}
			break;
		case IEEE80211_CONTROL_FRAME: // Control
			{
				const Dot11Control * ctrlFrame = pdu->find_pdu<Dot11Control>();
				if (ctrlFrame) {
					JSONObject * control = Dot11Control2String(ctrlFrame);
					if (control == NULL) {
						LOG_ERROR("Failed to parsing control frame!");
						delete doc;
						return NULL;
					}
					doc->Add("control", control);
				}
			}
			break;
		case IEEE80211_DATA_FRAME: // Data
			{
				const Dot11Data * dataFrame = pdu->find_pdu<Dot11Data>();
				if (dataFrame) {
					Dot11DataObjects * data = Dot11Data2String(dataFrame);
					if (data == NULL) {
						LOG_ERROR("Failed to parsing data frame!");
						delete doc;
						return NULL;
					}

					// Add the different elements
					if (data->QoS) {
						doc->Add("qos", data->QoS);
					}
					if (data->wep) {
						doc->Add("wep", data->wep);
					}
					if (data->tkip) {
						doc->Add("tkip", data->tkip);
					}
					if (data->ccmp) {
						doc->Add("ccmp", data->ccmp);
					}
					if (data->data) {
						doc->Add("data", data->data);
					}
				}
			}
			break;
		default:
			// "Should" never happen except maybe when packet is corrupted
			LOG_ERROR("There is something clearly wrong, packet isn't data, manament or control!");
			delete doc;
			return NULL;
			break;
	}

	return doc;
}

JSONObject * wifibeat::utils::tins::radiotap2String(const RadioTap * header)
{
	// XXX: For now radiotap parsing is disabled.
	if (header == NULL) {
		return NULL;
	}
	JSONObject * ret = new JSONObject();

	return ret;
}

JSONObject * wifibeat::utils::tins::Dot11ToString(const Dot11 * frame)
{
	if (frame == NULL) {
		return NULL;
	}

	const string typeSubtypeArray[4][16] = {
		{ "Association Request", "Association Response", "Ressociation Request", "Reassociation Response", "Probe Request", "Probe Response", "Reserved", "Reserved", "Beacon", "Announcement Traffic Indication Message (ATIM)", " Disassociation", "Authentication", "Deauthentitcation", "Action", "Action No ACK", "Reserved" },
		{ "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Control Wrapper", "Block ACK Request", "Block ACK", "PS-Poll", "Ready to send", "Clear to send", "Acknowledgement", "CF End", "CF End + CF ACK" },
		{ "Data", "Data + CF-ACK", "Data + CF-Poll", "Data + CF-Ack + CF-Poll", "Null function (No data)", "CF-ACK (No data)", "CF-Poll (No data)", "CF-ACK + CF-Poll (No data)", "QoS Data", "Reserved", "QoS Data + CF-Poll", "QoS Data + CF-ACK + CF-Poll", "QoS Null Data", "Reserved", "QoS Data + CF-Poll (no data)", "QoS CF-ACK + CF-Poll (no data):" },
		{ "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid", "Invalid" }
	};

	const string typeArray[4] { "Management frame", "Control frame", "Data frame", "Invalid" };

	JSONObject * ret = new JSONObject();
	JSONObject * fc = new JSONObject(); // Flags + FC

	ret->Add("size", frame->size());
	fc->Add("version", frame->protocol());
	unsigned int frameType = frame->type();
	fc->Add("type", frameType);
	fc->Add("type_str", typeArray[frameType]);
	unsigned int frameSubtype = frame->subtype();
	fc->Add("subtype", frameSubtype);

	// Display type/subtype string
	fc->Add("type_subtype", typeSubtypeArray[frameType][frameSubtype]);

	// Duration
	ret->Add("duration", frame->duration_id());


	
	// ToDS, FromDS
	bool tods = frame->to_ds() != 0;
	fc->Add("tods", tods);
	bool fromds = frame->from_ds() != 0;
	fc->Add("fromds", fromds);
	fc->Add("ds", (fromds*10)+tods); // Aggregate field 
	fc->Add("frag", frame->more_frag() != 0);
	fc->Add("retry", frame->retry() != 0);
	fc->Add("pwrmgt", frame->power_mgmt() != 0);
	fc->Add("moredata", frame->more_frag() != 0);
	fc->Add("protected", frame->wep() != 0);
	fc->Add("order", frame->order() != 0);

	// Add flags
	ret->Add("fc", fc);

	// Addresses
	ret->Add("ra", stringHelper::mac2str(frame->addr1()));

	// Control frames only have one address
	if (frameType == IEEE80211_CONTROL_FRAME) {
		const Dot11ControlTA * control_ta = frame->find_pdu<Dot11ControlTA>();
		if (control_ta) {
			string ta = stringHelper::mac2str(control_ta->target_addr());
			ret->Add("ta", ta);
		}
	} else {
		string addr1, addr2, addr3, addr4;
		const Dot11Data * data = frame->find_pdu<Dot11Data>();
		if (data) {
			addr1 = stringHelper::mac2str(data->addr1());
			addr2 = stringHelper::mac2str(data->addr2());
			addr3 = stringHelper::mac2str(data->addr3());
			if (tods && fromds) {
				addr4 = stringHelper::mac2str(data->addr4());
			}

			// Also take the opportunity to get fragment and sequence number.
			ret->Add("frag", data->frag_num());
			ret->Add("seq", data->seq_num());
		} else {
			const Dot11ManagementFrame * mgmt = frame->find_pdu<Dot11ManagementFrame>();
			if (mgmt) {
				addr1 = stringHelper::mac2str(mgmt->addr1());
				addr2 = stringHelper::mac2str(mgmt->addr2());
				addr3 = stringHelper::mac2str(mgmt->addr3());
				if (tods && fromds) {
					addr4 = stringHelper::mac2str(mgmt->addr4());
				}
				// Also take the opportunity to get fragment and sequence number.
				ret->Add("frag", mgmt->frag_num());
				ret->Add("seq", mgmt->seq_num());
			}
		}

		if (!tods) {
			if (!fromds) {
				ret->Add("da", addr1);
				ret->Add("ta", addr2);
				ret->Add("sa", addr2);
				ret->Add("bssid", addr3);
			} else {
				ret->Add("da", addr1);
				ret->Add("ta", addr2);
				ret->Add("sa", addr3);
				ret->Add("bssid", addr2);
				ret->Add("sta", addr1);
			}
		} else {
			// ToDS = 1
			if (!fromds) {
				ret->Add("da", addr3);
				ret->Add("ta", addr2);
				ret->Add("sa", addr2);
				ret->Add("bssid", addr1);
				ret->Add("sta", addr2);
			} else {
				// WDS
				ret->Add("wds", 1ULL);
				ret->Add("da", addr2);
				ret->Add("ta", addr3);
				ret->Add("sa", addr4);
			}
		}
	}

	return ret;
}



JSONObject * wifibeat::utils::tins::Dot11Management2String(const Dot11ManagementFrame * frame)
{
	if (frame == NULL) {
		return NULL;
	}
	JSONObject * wlan_mgt = new JSONObject();

	#define AMOUNT_STATUS_CODES 104
	const string statusCodeTranslation[AMOUNT_STATUS_CODES] = {
		"Successful", "Unspecified failure", "TDLS wakeup schedule rejected but alternative schedule provided", "TDLS wakeup schedule rejected",
		"Reserved", "Security disabled", "Unacceptable lifetime", "Not in same BSS", "Reserved", "Reserved",
		"Cannot support all requested capabilities in the Capability Information field", "Reassociation denied due to inability to confirm that association exists",
		"Association denied due to reason outside the scope of this standard", "Responding STA does not support the specified authentication algorithm",
		"Received an Authentication frame with authentication transaction sequence number out of expected sequence",
		"Authentication rejected because of challenge failure", "Authentication rejected due to timeout waiting for next frame in sequence",
		"Association denied because AP is unable to handle additional associated STAs",
		"Association denied due to requesting STA not supporting all of the data rates in the BSSBasicRateSet parameter",
		"Association denied due to requesting STA not supporting the short preamble option",
		"Association denied due to requesting STA not supporting the PBCC modulation option",
		"Association denied due to requesting STA not supporting the Channel Agility option",
		"Association request rejected because Spectrum Management capability is required",
		"Association request rejected because the information in the Power Capability element is unacceptable",
		"Association request rejected because the information in the Supported Channels element is unacceptable",
		"Association denied due to requesting STA not supporting the Short Slot Time option",
		"Association denied due to requesting STA not supporting the DSSS-OFDM option",
		"Reserved Association denied because the requesting STA does not support HT features", "R0KH unreachable",
		"Association denied because the requesting STA does not support the phased coexistence operation (PCO) transition time required by the AP",
		"Association request rejected temporarily; try again later", "Robust Management frame policy violation", "Unspecified, QoS-related failure",
		"Association denied because QoS AP or PCP has insufficient bandwidth to handle another QoS STA",
		"Association denied due to excessive frame loss rates and/or poor conditions on current operating channel",
		"Association (with QoS BSS) denied because the requesting STA does not support the QoS facility", "Reserved",
		"The request has been declined", "The request has not been successful as one or more parameters have invalid values",
		"The allocation or TS has not been created because the request cannot be honored; however, a suggested TSPEC/DMG TSPEC is provided so that the initiating STA may attempt to set another allocation or TSPEC/DMG TSPEC",
		"Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7",
		"Invalid group cipher", "Invalid pairwise cipher", "Invalid AKMP", "Unsupported RSN information element version",
		"Invalid RSN information element capabilities", "Cipher suite rejected because of security policy",
		"The TS per allocation has not been created; however, the PCP/HC may be capable of creating a TS or allocation, in response to a request, after the time indicated in the TS Delay element",
		"Direct link is not allowed in the BSS by policy", "The Destination STA is not present within this BSS",
		"The Destination STA is not a QoS STA", "Association denied because the ListenInterval is too large", "Invalid FT Action frame count",
		"Invalid pairwise master key identifier (PMKID)", "Invalid MDIE", "Invalid FTIE", "Requested TCLAS processing is not supported by the PCP/AP",
		"The PCP/AP has insufficient TCLAS processing resources to satisfy the request",
		"The TS has not been created because the request cannot be honored; however, the PCP/HC suggests the STA to transition to other BSSs to setup the TS",
		"GAS Advertisement Protocol not supported", "No outstanding GAS request", "GAS Response not received from the Advertisement Server",
		"STA timed out waiting for GAS Query Response", "GAS Response is larger than query response length limit",
		"Request refused because home network does not support request", "Advertisement Server in the network is not currently reachable",
		"Reserved", "Request refused due to permissions received via SSPN interface", "Request refused because PCP/AP does not support unauthenticated access",
		"Reserved", "Reserved", "Reserved", "Invalid contents of RSNIE", "U-APSD Coexistence is not supported", "Requested U-APSD Coexistence mode is not supported",
		"Requested Interval/Duration value cannot be supported with U-APSD Coexistence", "Authentication is rejected because an Anti-Clogging Token is required",
		"Authentication is rejected because the offered finite cyclic group is not supported",
		"The TBTT adjustment request has not been successful because the STA could not find an alternative TBTT", "Transmission failure",
		"Requested TCLAS Not Supported", "TCLAS Resources Exhausted", "Rejected with Suggested BSS Transition", "Reject with recommended schedule",
		"Reject because no wakeup schedule specified", "Success, the destination STA is in power save mode", "FST pending, in process of admitting FST session",
		"Performing FST now", "FST pending, gap(s) in Block Ack window", "", "", "Reject because of U-PID setting",
		"(Re)association refused for some external reason", "(Re)association refused because of memory limits at the AP",
		"(Re)association refused because emergency services are not supported at the AP", "GAS query response not yet received",
		"Reject since the request is for transition to a frequency band subject to DSE procedures and FST initiator is a dependent STA",
		"Reserved", "Reserved", "The association has been denied; however, one or more Multi-band elements are included that can be used by the receiving STA to join the BSS",
		"The request failed due to a reservation conflict", "The request failed due to exceeded MAF limit", "The request failed due to exceeded MCCA track limit",
		"Association denied because the information in the Spectrum Management field is unacceptable" };

	#define AMOUNT_REASON_CODES 67
	const string reasonCodeTranslation[AMOUNT_REASON_CODES] = {
		"", "Unspecified reason", "Previous authentication no longer valid", "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
		"Disassociated due to inactivity", "Disassociated because AP is unable to handle all currently associated STAs",
		"Class 2 frame received from nonauthenticated STA", "Class 3 frame received from nonassociated STA", "Disassociated because sending STA is leaving (or has left) BSS",
		"STA requesting (re)association is not authenticated with responding STA", "Disassociated because the information in the Power Capability element is unacceptable",
		"Disassociated because the information in the Supported Channels element is unacceptable", "Reserved",
		"Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7",
		"Message integrity code (MIC) failure", "4-Way Handshake timeout", "Group Key Handshake timeout",
		"Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame", "Invalid group cipher",
		"Invalid pairwise cipher", "Invalid AKMP", "Unsupported RSN information element version", "Invalid RSN information element capabilities",
		"IEEE 802.1X authentication failed", "Cipher suite rejected because of the security policy",
		"TDLS direct-link teardown due to TDLS peer STA unreachable via the TDLS direct link", "TDLS direct-link teardown for unspecified reason",
		"Disassociated because session terminated by SSP request", "Disassociated because of lack of SSP roaming agreement",
		"Requested service rejected because of SSP cipher suite or AKM requirement ", "Requested service not authorized in this location",
		"TS deleted because QoS AP lacks sufficient bandwidth for this QoS STA due to a change in BSS service characteristics or operational mode",
		"Disassociated for unspecified, QoS-related reason", "Disassociated because QoS AP lacks sufficient bandwidth for this QoS STA",
		"Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions",
		"Disassociated because STA is transmitting outside the limits of its TXOPs", "Requested from peer STA as the STA is leaving the BSS (or resetting)",
		"Requested from peer STA as it does not want to use the mechanism", "Requested from peer STA as the STA received frames using the mechanism for which a setup is required",
		"Requested from peer STA due to timeout", "Peer STA does not support the requested cipher suite", "Disassociated because authorized access limit reached",
		"Disassociated due to external service requirements", "Invalid FT Action frame count", "Invalid pairwise master key identifier (PMKI)", "Invalid MDE",
		"Invalid FTE", "SME cancels the mesh peering instance with the reason other than reaching the maximum number of peer mesh STAs",
		"The mesh STA has reached the supported maximum number of peer mesh STAs",
		"The received information violates the Mesh Configuration policy configured in the mesh STA profile",
		"The mesh STA has received a Mesh Peering Close message requesting to close the mesh peering",
		"The mesh STA has re-sent dot11MeshMaxRetries Mesh Peering Open messages, without receiving a Mesh Peering Confirm message",
		"The confirmTimer for the mesh peering instance times out", "The mesh STA fails to unwrap the GTK or the values in the wrapped contents do not match",
		"The mesh STA receives inconsistent information about the mesh parameters between Mesh Peering Management frames",
		"The mesh STA fails the authenticated mesh peering exchange because due to failure in selecting either the pairwise ciphersuite or group ciphersuite",
		"The mesh STA does not have proxy information for this external destination", "The mesh STA does not have forwarding information for this destination",
		"The mesh STA determines that the link to the next hop of an active path in its forwarding information is no longer usable",
		"The Deauthentication frame was sent because the MAC address of the STA already exists in the mesh BSS. See 11.3.3 (Additional mechanisms for an AP collocated with a mesh STA)",
		"The mesh STA performs channel switch to meet regulatory requirements", "The mesh STA performs channel switch with unspecified reason" };

	// Tagged parameters
	const Tins::Dot11::options_type mgtOptions = frame->options();
	if (ParseDot11ManagementOptions(mgtOptions, wlan_mgt, frame) == false) {
		wlan_mgt->Add("parse_failure");
	}
				
	switch (frame->subtype()) {
		case MGT_FRAME_ASSOC_REQUEST:
			// Association request
			{
				const Dot11AssocRequest * ar = frame->find_pdu<Dot11AssocRequest>();
				if (!ar) {
					delete wlan_mgt;
					return NULL;
				}

				// Fixed parameters
				JSONObject * fixedParams = new JSONObject();
				fixedParams->Add("listen_ival", ar->listen_interval());

				// Capabilities
				Tins::Dot11ManagementFrame::capability_information ci = ar->capabilities();
				JSONObject * capabilities = ParseCapabilities(ci);

				// Link them
				fixedParams->Add("capabilities", capabilities);
				wlan_mgt->Add("fixed", fixedParams);
				break;
			}
		case MGT_FRAME_ASSOC_RESPONSE:
			// Association response
			{
				const Dot11AssocResponse * ar = frame->find_pdu<Dot11AssocResponse>();
				if (!ar) {
					delete wlan_mgt;
					return NULL;
				}

				// Fixed parameters
				JSONObject * fixedParams = new JSONObject();

				// Capabilities
				Tins::Dot11ManagementFrame::capability_information ci = ar->capabilities();
				JSONObject * capabilities = ParseCapabilities(ci);

				// Status code
				uint16_t status_code = ar->status_code();
				fixedParams->Add("status_code", status_code);
				if (status_code < AMOUNT_STATUS_CODES && statusCodeTranslation[status_code].size() != 0) {
					fixedParams->Add("status_code_parsed",  statusCodeTranslation[status_code]);
				}

				// Association ID
				fixedParams->Add("aid", ar->aid());

				// Link them
				fixedParams->Add("capabilities", capabilities);
				wlan_mgt->Add("fixed", fixedParams);
				break;
			}
			break;
		case MGT_FRAME_PROBE_RESPONSE:
			// Probe response (identical to beacon)
			{
				const Dot11ProbeResponse * pr = frame->find_pdu<Dot11ProbeResponse>(); 
				if (!pr) {
					delete wlan_mgt;
					return NULL;
				}

				// Fixed parameters
				JSONObject * fixedParams = new JSONObject();

				fixedParams->Add("timestamp", (unsigned long long int)pr->timestamp());
				// flawfinder: ignore
				char tsStr [19] = { 0 };
				snprintf(tsStr, sizeof(tsStr), "0x%016llx", (unsigned long long int)pr->timestamp());
				fixedParams->Add("timestamp_hex", tsStr);
				fixedParams->Add("beacon", pr->interval());
				fixedParams->Add("beacon_interval_usec", pr->interval() * 1024);

				// Capabilities
				Tins::Dot11ManagementFrame::capability_information ci = pr->capabilities();
				JSONObject * capabilities = ParseCapabilities(ci);

				fixedParams->Add("capabilities", capabilities);
				wlan_mgt->Add("fixed", fixedParams);
				break;
			}
		case MGT_FRAME_BEACON:
			// Beacon
			{
				const Dot11Beacon * beacon = frame->find_pdu<Dot11Beacon>(); 
				if (!beacon) {
					delete wlan_mgt;
					return NULL;
				}

				// Fixed parameters
				JSONObject * fixedParams = new JSONObject();

				fixedParams->Add("timestamp", (unsigned long long int)beacon->timestamp());
				// flawfinder: ignore
				char tsStr [19] = { 0 };
				snprintf(tsStr, sizeof(tsStr), "0x%016llx", (unsigned long long int)beacon->timestamp());
				fixedParams->Add("timestamp_hex", tsStr);
				fixedParams->Add("beacon", beacon->interval());
				fixedParams->Add("beacon_interval_usec", beacon->interval() * 1024);

				// Capabilities
				Tins::Dot11ManagementFrame::capability_information ci = beacon->capabilities();
				JSONObject * capabilities = ParseCapabilities(ci);

				fixedParams->Add("capabilities", capabilities);
				wlan_mgt->Add("fixed", fixedParams);
				break;
			}
		case MGT_FRAME_AUTHENTICATION:
			// Authentication
			{
				const Dot11Authentication * authFrame = frame->find_pdu<Dot11Authentication>();
				if (!authFrame) {
					delete wlan_mgt;
					return NULL;
				}

				// TODO: Handle shared authentication (challenge text/response)

				// Fixed parameters
				JSONObject * fixedParams = new JSONObject();
				JSONObject * auth = new JSONObject();

				uint16_t alg = authFrame->auth_algorithm();
				auth->Add("alg", alg);
				auth->Add("type", (alg == 0) ? "Open" : "Shared");
				fixedParams->Add("auth_seq", authFrame->auth_seq_number());

				uint16_t status_code = authFrame->status_code();
				fixedParams->Add("status_code", status_code);
				if (status_code < AMOUNT_STATUS_CODES && statusCodeTranslation[status_code].size() != 0) {
					fixedParams->Add("status_code_parsed",  statusCodeTranslation[status_code]);
				}


				// Link them
				fixedParams->Add("auth", auth);
				wlan_mgt->Add("fixed", fixedParams);
				break;
			}
		case MGT_FRAME_DEAUTHENTICATION:
			// Deauth
			{
				const Dot11Deauthentication * deauth = frame->find_pdu<Dot11Deauthentication>();
				if (!deauth) {
					delete wlan_mgt;
					return NULL;
				}

				// Fixed parameters
				JSONObject * fixedParams = new JSONObject();

				uint16_t reason_code = deauth->reason_code();
				fixedParams->Add("reason_code", reason_code);
				if (reason_code < AMOUNT_REASON_CODES && reasonCodeTranslation[reason_code].size() != 0) {
					fixedParams->Add("reason_code_parsed",  reasonCodeTranslation[reason_code]);
				}

				// Link them
				wlan_mgt->Add("fixed", fixedParams);
				break;
			}
		default:
			break;
	}

	return wlan_mgt;
}

JSONObject * wifibeat::utils::tins::ParseCapabilities(Tins::Dot11ManagementFrame::capability_information & ci)
{
	JSONObject * capabilities = new JSONObject();
	capabilities->Add("ess", ci.ess());
	capabilities->Add("ibss", ci.ibss());
	
	JSONObject * cfpoll = new JSONObject();
	cfpoll->Add("ap", ci.cf_poll()); // Not entirely sure if method is correct
	capabilities->Add("cfpoll", cfpoll);
	
	capabilities->Add("privacy", ci.privacy());
	capabilities->Add("preamble", ci.short_preamble());
	capabilities->Add("pbcc", ci.pbcc());
	capabilities->Add("agility", ci.channel_agility());
	capabilities->Add("spec_man", ci.spectrum_mgmt());
	capabilities->Add("short_slot_time", ci.sst());
	capabilities->Add("apsd", ci.apsd());
	capabilities->Add("radio_measurement", ci.radio_measurement());
	capabilities->Add("dsss_ofdm", ci.dsss_ofdm());
	capabilities->Add("del_blk_ack", ci.delayed_block_ack());
	capabilities->Add("imm_blk_ack", ci.immediate_block_ack());
	
	return capabilities;
}

bool wifibeat::utils::tins::ParseDot11ManagementOptions(const Tins::Dot11::options_type & mgtOptions, JSONObject * wlan_mgt, const Dot11ManagementFrame * frame)
{
	if (wlan_mgt == NULL) {
		return false;
	}
	JSONObject * ht = NULL; // Used in more than one IE
	// So, if NULL, not used, don't add
	// There can be 2 (or more) MCS set
	vector<JSONObject *> mcssetVector;

	vector<JSONObject *> optionsVector;
	for (const Tins::Dot11::option & opt: mgtOptions) {
		JSONObject * tag = new JSONObject();
		unsigned int optNr = opt.option();
		tag->Add("number", optNr);
		unsigned char len = opt.length_field();
		tag->Add("length", len);
		


		// TODO: Do a better length verification for each tag when accessing data
		switch (optNr) {
			case IE_ESSID:
			{
				// TODO: Build array (empty ones are more complex)
				tag->Add("name", string("ESSID"));
				tag->Add("value", frame->ssid());
				if (frame) {
					if (frame->ssid().empty()) {
						wlan_mgt->Add("ssid");
					} else {
						wlan_mgt->Add("ssid", frame->ssid());
					}
				}
				if (len == 0) {
					wlan_mgt->Add("ssid_broadcast", true);
				} else if (len > 32) {
					tag->Add("ssid_too_long");
				}
				break;
			}
			case IE_SUPPORTED_RATES:
			{
				tag->Add("name", string("Supported rates"));
				if (len != 0) {
					vector<unsigned int> rates;
					vector<double> ratesValue;

					for (unsigned int i = 0; i < opt.length_field(); ++i) {
						unsigned char val = opt.data_ptr()[i];
						if (0xFF != val) { 
							rates.push_back(val);
							if (val > 0x80) {
								val -= 0x80;
							}
							ratesValue.push_back(val / 2.0); // Real rate
						} else {
							// Special case: BSS requires support for mandatory features of HT PHY (IEEE 802.11 - Clause 20)
							ratesValue.push_back(-1.0);
						}
					}
					wlan_mgt->Add("supported_rates", rates);
					wlan_mgt->Add("supported_rates_mbit", ratesValue);
					tag->Add("supported_rates_mbit", ratesValue);
				}
				break;
			}
			case IE_DS_PARAM_SET:
			{
				tag->Add("name", string("DS parameter set"));
				if (len != 0) {
					JSONObject * currentChannel = new JSONObject();
					currentChannel->Add("current_channel", opt.data_ptr()[0]);
					wlan_mgt->Add("ds", currentChannel);
				}
				break;
			}
			case IE_TIM:
			{
				tag->Add("name", string("Traffic Indication Map (TIM)"));
				if (len >= 3) {
					// Tim Object
					JSONObject * tim = new JSONObject();
					tim->Add("dtim_count", frame->tim().dtim_count);
					tim->Add("dtim_period", frame->tim().dtim_period);

					// Partial virtual bitmap item
					vector<unsigned int>  pvb;
					for (uint8_t item: frame->tim().partial_virtual_bitmap) {
						pvb.push_back(item);
					}
					tim->Add("partial_virtual_bitmap", pvb);

					// bmapctl item
					JSONObject * bmapctl = new JSONObject();
					unsigned int bmapctl_value = frame->tim().bitmap_control;
					bmapctl->Add("value", bmapctl_value);
					bmapctl->Add("multicast", bmapctl_value % 2);
					bmapctl->Add("offset", bmapctl_value / 2);
					
					// Link
					tim->Add("bmapctl", bmapctl);
					wlan_mgt->Add("tim", tim);
				} else {
					tag->Add("invalid", string("incorrect length, should be >= 3"));
				}
				break;
			}
			case IE_COUNTRY_INFO:
			{
				tag->Add("name", string("Country information"));
				if (len >= 3) {
					JSONObject * country_info = new JSONObject();
					// flawfinder: ignore
					char ccode[3] = { 0 };
					// flawfinder: ignore
					memcpy(ccode, opt.data_ptr(), 2);
					country_info->Add("code", ccode);
					unsigned char env = opt.data_ptr()[2];
					country_info->Add("environment", env);
					switch (env) {
						case 0x20:
							country_info->Add("environment_parsed", string("any"));
							break;
						default:
							break;
					}

					// Country information item
					vector<JSONObject *> fnmVector;
					for (unsigned int i = 3; i + 3 <= opt.data_size(); i += 3) {
						JSONObject * fnm = new JSONObject();
						fnm->Add("fcn", opt.data_ptr()[i]); // First channel number
						fnm->Add("nc", opt.data_ptr()[i + 1]); // Number of channels
						fnm->Add("mtpl", opt.data_ptr()[i + 2]); // Maximum transmit power level in dBm
						fnmVector.push_back(fnm);
					}
					
					// Link
					country_info->Add("fnm", fnmVector);
					wlan_mgt->Add("country_info", country_info);
				}
				break;
			}
			case IE_QBSS_LOAD_ELEMENT:
			{
				// Channel load information
				tag->Add("name", string("QBSS Load Element"));
				// See chinese ssid name from aircrack-ng (frame 9)
				break;
			}
			case IE_POWER_CONSTRAINT:
			{
				tag->Add("name", string("Power constraint"));
				// See wpa-psk-linksys.pcap from aircrack-ng (frame 9)
				break;
			}
			case IE_ERP_INFO42:
			{
				tag->Add("name", string("ERP Information (42)"));
				// Allow jumping to #47, parsing is identical, so no break;
				[[fallthrough]];
				//fallthrough
			}
			case IE_ERP_INFO47:
			{
				if (optNr == 47) {
					tag->Add("name", string("ERP Information (47)"));
				}
				if (len == 1) {
					JSONObject * erp_information = new JSONObject();
					std::bitset<8> bsTemp(opt.data_ptr()[0]);
					erp_information->Add("erp_present", bsTemp[0]);
					erp_information->Add("use_protection", bsTemp[1]);
					erp_information->Add("barker_preamble_mode", bsTemp[2]);
					erp_information->Add("reserved", (opt.data_ptr()[0]) / 8ULL);
					wlan_mgt->Add("erp_info", erp_information);
				}
				break;
			}
			case IE_HT_CAPA_D110:
			{
				tag->Add("name", string("HT Capabilities (802.11n D1.10)"));
				if (ht == NULL) {
					ht = new JSONObject();
				}
				if (len >= 2) {
					// HT capabilities
					JSONObject * capabilities = new JSONObject();
					bitset<8> byte0(opt.data_ptr()[0]);
					capabilities->Add("ldpccoding", byte0[0]); // LDPC Coding capbility?
					capabilities->Add("width", byte0[1]); // Supported channel witdth
					capabilities->Add("width_mhz", (byte0[1]) ? 40ULL : 20ULL); // Intepreted version
					unsigned int sm = (byte0[3] * 2) + byte0[2];
					capabilities->Add("sm", sm); // SM Power save?
					if (sm == 3) {
						capabilities->Add("sm_parsed", string("power save disabled"));
					}
					capabilities->Add("green", byte0[4]); // Green field preamble accepted?
					capabilities->Add("short20", byte0[5]); // Short Guard Interval for 20MHz?
					capabilities->Add("short40", byte0[6]); // Short Guard Interval for 40MHz?
					capabilities->Add("txstbc", byte0[7]);
					
					bitset<8> byte1(opt.data_ptr()[1]);
					unsigned int rxstbc = (byte1[1] * 2) + byte1[0];
					capabilities->Add("rxstbc", rxstbc);
					if (rxstbc == 0) {
						capabilities->Add("rxstbc_parsed", "disabled");
					}
					capabilities->Add("delayedblockack", byte1[2]);
					capabilities->Add("amsdu", byte1[3]);
					if (byte1[3]) {
						capabilities->Add("max_amsdu_length", 7935ULL);
					}
					capabilities->Add("dsscck", byte1[4]); // Will/Can use DSSS or CCK in 40MHz?
					capabilities->Add("psmp", byte1[5]); // PSMP Support?
					capabilities->Add("40mhzintolerant", byte1[6]); // Is 40MHz transmission restriced/not allowed?
					capabilities->Add("lsig", byte1[7]); // L-SIG TXOP Protection support?

					ht->Add("capabilities", capabilities);
				}
				if (len >= 3) {
					bitset<8> byte2(opt.data_ptr()[2]);
					JSONObject * ampduparam = new JSONObject();
					unsigned int maxlength = (byte2[1] * 2) + byte2[0];
					ampduparam->Add("maxlength", maxlength);
					if (maxlength == 3) {
						ampduparam->Add("maxlength_parsed", 65535ULL);
					}
					unsigned int mpdudensity = (byte2[4] * 4) + (byte2[3] * 2) + byte2[2];
					ampduparam->Add("mpdudensity", mpdudensity);
					if (mpdudensity == 6) {
						ampduparam->Add("mpdudensity_usec", 8ULL);
					}
					unsigned int reserved = (byte2[7] * 4) + (byte2[6] * 2) + byte2[5];
					ampduparam->Add("reserved", reserved);
					
					ht->Add("ampduparam", ampduparam);
				}
				if (len >= 19) {
					// Same stuff in IE 61
					JSONObject * mcsset = ParseMCSSet(opt.data_ptr(), len, 3);

					if (!mcsset) {
						mcsset = new JSONObject();
						mcsset->Add("failed", "MCS Set parsing failure, report this frame.");
					}
					mcsset->Add("tag", optNr);
					mcssetVector.push_back(mcsset);
					//ht->Add("mcsset", mcsset);
				}
				if (len >= 21) {
					JSONObject * htex = new JSONObject();
					JSONObject * capabilities = new JSONObject();

					bitset<8> byte19(opt.data_ptr()[19]);
					capabilities->Add("pco", byte19[4]); // Transmitter PCO Support?
					capabilities->Add("transtime", (byte19[2] * 2) + byte19[1]); // Time to transition between 20/40MHz?
					
					bitset<8> byte20(opt.data_ptr()[20]);
					capabilities->Add("mcs", (byte20[1] * 2) + byte20[0]); // MCS Freedback
					capabilities->Add("htc", byte20[2]); // High Throughput support?
					capabilities->Add("rdresponder", byte20[3]); // Reverse direction responder

					// Link them
					htex->Add("capabilities", capabilities);
					wlan_mgt->Add("htex", htex);
				}
				if (len >= 25) {
					JSONObject * txbf = new JSONObject();

					bitset<8> byte21(opt.data_ptr()[21]);
					txbf->Add("txbf", byte21[0]); // Transmit beamforming support?
					txbf->Add("rxss", byte21[1]); // Receive staggered sounding support
					txbf->Add("txss", byte21[2]); // Transmit staggered sounding support
					txbf->Add("rxndp", byte21[3]); // Receive Null Data packet (NDP) support
					txbf->Add("txndp", byte21[4]); // Transmit Null Data packet (NDP) support
					txbf->Add("impltxbf", byte21[5]); // Implicit TxBF capability support
					unsigned int calibration = (byte21[7] * 2) + byte21[6];
					txbf->Add("calibration", calibration);
					if (calibration == 0) {
						txbf->Add("calibration_parsed", "incapable");
					}

					bitset<8> byte22(opt.data_ptr()[22]);
					JSONObject * csi = new JSONObject();
					csi->Add("value", byte22[0]);
					JSONObject * fm = new JSONObject();
					JSONObject * uncompressed = new JSONObject();
					uncompressed->Add("tbf", byte22[1]);
					JSONObject * compressed = new JSONObject();
					compressed->Add("tbf", byte22[2]);
					txbf->Add("rcsi", (byte22[4] * 2) + byte21[3]);
					uncompressed->Add("rbf", (byte22[6] * 2) + byte21[5]);

					bitset<8> byte23(opt.data_ptr()[22]);
					compressed->Add("bf", byte22[7] + (byte23[0] * 2));
					txbf->Add("mingroup", byte23[1] + (byte23[2] * 2));
					unsigned int maxant = byte23[3] + (byte23[4] * 2);
					txbf->Add("csinumant", maxant);
					// Assuming it's value + 1
					txbf->Add("csinumant_parsed", maxant + 1);
					
					maxant = byte23[5] + (byte23[6] * 2);
					uncompressed->Add("maxant", maxant);
					uncompressed->Add("maxant_parsed", maxant + 1);
					
					maxant = byte23[7];

					bitset<8> byte24(opt.data_ptr()[22]);
					maxant += (byte24[0] * 2);
					compressed->Add("maxant", maxant);
					compressed->Add("maxant_parsed", maxant + 1);
					unsigned int maxrows = byte24[1] + (byte24[2] * 2);
					csi->Add("maxrows", maxrows);
					csi->Add("maxrows_parsed", maxrows + 1);
					unsigned int channelest = byte24[3] + (byte24[4] * 2);
					txbf->Add("channelest", channelest);
					txbf->Add("channelest_parsed", channelest + 1);
					txbf->Add("reserved", byte24[5] + (byte24[6] * 2) + (byte24[7] * 4));

					// Link
					fm->Add("compressed", compressed);
					fm->Add("uncompressed", uncompressed);
					txbf->Add("fm", fm);
					txbf->Add("csi", csi);
					wlan_mgt->Add("txbf", txbf);
				}
				// XXX: There shouldn't be anything after that but we never know
				if (len >= 26) {
					JSONObject * asel = new JSONObject();
					bitset<8> byte25(opt.data_ptr()[25]);
					
					asel->Add("capable", byte25[0]);
					asel->Add("txcsi", byte25[1]);
					asel->Add("txif", byte25[2]);
					asel->Add("csi", byte25[3]);
					asel->Add("if", byte25[4]);
					asel->Add("rx", byte25[5]);
					asel->Add("sppdu", byte25[6]);
					asel->Add("reserved", byte25[7]);
					
					wlan_mgt->Add("asel", asel);
				}
				
				// Don't add it right now, it is used in another IE
				//wlan_mgt->Add("ht", ht);
				break;
			}
			case IE_RSN_INFORMATION:
			{
				const Tins::RSNInformation & rsninformation = frame->rsn_information();
				
				tag->Add("name", string("RSN Information"));
				JSONObject * rsn = new JSONObject();
				rsn->Add("version", rsninformation.version());
				
				// Group cipher suite
				JSONObject * gcs = ParseRSNInformationCipherSuite(rsninformation.group_suite());

				// Pairwise cipher suite
				JSONObject * pcs = new JSONObject();
				vector<JSONObject *> pcsVector;
				for (RSNInformation::CypherSuites cs: rsninformation.pairwise_cyphers()) {
					pcsVector.push_back(ParseRSNInformationCipherSuite(cs));
				}
				pcs->Add("count", (unsigned int)pcsVector.size());
				pcs->Add("list", pcsVector);

				// Authentication Key Management
				JSONObject * akms = new JSONObject();
				vector<JSONObject *> akmVector;
				for (RSNInformation::AKMSuites item: rsninformation.akm_cyphers()) {
					JSONObject * jo = new JSONObject();

					// OUI
					unsigned int oui = (((0x00 * 256) + 0x0f) * 256) + 0xac;
					jo->Add("oui", oui); // 00-0f-ac, always

					// Display suite
					// TODO: Add more
					switch(item) {
						case RSNInformation::AKMSuites::EAP:
							jo->Add("type", 1ULL);
							jo->Add("value", (oui * 256) + 1);
							jo->Add("value_parsed", string("EAP"));
							break;
						case RSNInformation::AKMSuites::PSK:
							jo->Add("type", 2ULL);
							jo->Add("value", (oui * 256) + 2);
							jo->Add("value_parsed", string("PSK"));
							break;
						default:
							jo->Add("type", string("unknown"));
							break;
						
					}
					akmVector.push_back(jo);
				}
				akms->Add("count", (unsigned int)akmVector.size());
				akms->Add("list", akmVector);

				// RSN Information
				JSONObject * capabilities = new JSONObject();
				bitset<16> capa(rsninformation.capabilities());
				capabilities->Add("preauth", capa[0]); // RSN Pre-Auth support?
				capabilities->Add("no_pairwise", capa[1]); // RSN No Pairwise capabilities
				unsigned int ptksa_rc = (capa[3]*2) + capa[2];
				capabilities->Add("ptksa_replay_counter", ptksa_rc); // Pairwise Key
				if (ptksa_rc == 0 || ptksa_rc == 3) {
					// XXX: Only know the value for 0 and 3 -> need to test with other values
					capabilities->Add("ptksa_replay_counter_parsed", ((ptksa_rc == 0) ? 1ULL : 16ULL) ); 
				}
				unsigned int gtksa_rc = (capa[5]*2) + capa[4];
				capabilities->Add("gtksa_replay_counter", gtksa_rc); // Group Key
				if (gtksa_rc == 0 || gtksa_rc == 3) {
					// XXX: Only know the value for 0 and 3 -> need to test with other values
					capabilities->Add("gtksa_replay_counter_parsed", ((gtksa_rc == 0) ? 1ULL : 16ULL) ); 
				}
				capabilities->Add("mfpr", capa[6]); // Management Frame protection required?
				capabilities->Add("mfpc", capa[7]); // Management Frame protection capable?
				capabilities->Add("jmr", capa[8]); // Join Multiband RSNA
				capabilities->Add("peerkey", capa[9]); // Enabled?

				// Link
				rsn->Add("capabilities", capabilities);
				rsn->Add("akms", akms);
				rsn->Add("pcs", pcs);
				rsn->Add("gcs", gcs);
				wlan_mgt->Add("rsn", rsn);
				break;
			}
			case IE_EXT_SUPPORTED_RATES:
			{
				tag->Add("name", string("Extended supported rates"));
				if (len != 0) {
					vector<unsigned int> rates;
					vector<double> ratesValue;
					for (unsigned int i = 0; i < opt.length_field(); ++i) {
						unsigned char val = opt.data_ptr()[i];
						if (0xFF != val) { 
							rates.push_back(val);
							if (val > 0x80) {
								val -= 0x80;
							}
							ratesValue.push_back(val / 2.0); // Real rate
						} else {
							// Special case: BSS requires support for mandatory features of HT PHY (IEEE 802.11 - Clause 20)
							ratesValue.push_back(-1.0);
						}
					}
					wlan_mgt->Add("extended_supported_rates", rates);
					wlan_mgt->Add("extended_supported_rates_mbit", ratesValue);
					tag->Add("extended_supported_rates_mbit", ratesValue);
				}
				break;
			}
			case IE_AP_CHANNEL_REPORT:
			{
				JSONObject * ap_channel_report = new JSONObject();
				if (len > 1) {
					unsigned int operating_class = opt.data_ptr()[0];
					tag->Add("name", "AP Channel report: Operating class " + std::to_string(operating_class));
					ap_channel_report->Add("operating_class", operating_class);
					vector <unsigned int> channel_list;
					for (unsigned short i = 1; i < opt.data_size(); ++i) {
						channel_list.push_back(opt.data_ptr()[i]);
					}
					ap_channel_report->Add("channel_list", channel_list);
				} else {
					tag->Add("name", string("AP Channel report: invalid!"));
				}

				// Link
				wlan_mgt->Add("ap_channel_report", ap_channel_report);
				break;
			}
			case IE_NEIGHBOR_REPORT:
			{
				tag->Add("name", string("Neighbor report"));
				// See chinese or mesh.pcap
				break;
			}
			case IE_MOBILITY_DOMAIN:
			{
				tag->Add("name", string("Mobility domain"));
				// See chinese or mesh.pcap
				break;
			}
			case IE_HT_INFO_D110:
			{
				tag->Add("name", string("HT Information (802.11n D1.10"));
				if (len != 22) {
					tag->Add("invalid", string("Invalid length, expected 22 bytes. Report this frame along with pcap"));
					break;
				}
				if (ht == NULL) {
					ht = new JSONObject();
				}
				JSONObject * info = new JSONObject();
				
				info->Add("primary channel", opt.data_ptr()[0]);
				
				// HT information subset (1/3)
				info->Add("delim1", opt.data_ptr()[1]);
				bitset<8> byte1(opt.data_ptr()[1]);

				// Channel offset
				unsigned int channeloffset = byte1[0] + (byte1[1] * 2);
				info->Add("secchanneloffset", channeloffset);
				switch (channeloffset) {
					case 0:
						info->Add("secchanneloffset_parsed", string("NoHT"));
						break;
					case 1:
						info->Add("secchanneloffset_parsed", string("HT+"));
						break;
					case 2:
						info->Add("secchanneloffset_parsed", string("Reserved"));
						break;
					default: // 3
						info->Add("secchanneloffset_parsed", string("HT-"));
						break;
				}

				// Channel width (20/40MHz)
				info->Add("channelwidth", byte1[2]);
				if (byte1[2]) {
					info->Add("channelwidth_parsed", string("Any channel width in the STA's Supported Channel Width Set"));
				} else {
					info->Add("channelwidth_parsed", string("20MHz channel width only"));
				}

				info->Add("rifs", byte1[3]);
				info->Add("psmponly", byte1[4]);
				unsigned int value = byte1[5] + (byte1[6] * 2) + (byte1[7] * 4);
				info->Add("value", value);
				info->Add("ssi_ms", (value + 1) * 5 );

				// HT Information subset (2/3)
				bitset<8> byte2(opt.data_ptr()[2]);
				unsigned int om = byte2[0] + (byte2[1] * 2);
				info->Add("operatingmode", om);
				switch(om) {
					case 0:
						info->Add("operatingmode_parsed", string("All STAs are - 20/40 MHz HT or in a 20/40 MHz BSS or are 20 MHz HT in a 20 MHz BSS"));
						break;
					case 1:
						info->Add("operatingmode_parsed", string("HT non-member protection mode"));
						break;
					case 2:
						info->Add("operatingmode_parsed", string("Only HT STAs in the BSS, however, there exists at least one 20 MHz STA"));
						break;
					default:
						info->Add("operatingmode_parsed", string("HT mixed mode"));
						break;
				}

				info->Add("greenfield", byte2[2]);
				info->Add("burstlim", byte2[3]);
				info->Add("obssnonht", byte2[4]);
				info->Add("reserved1", (opt.data_ptr()[2] / 32) + (opt.data_ptr()[3] * 8));

				// HT Information subset (3/3)
				info->Add("reserved2", opt.data_ptr()[4] % 64);
				bitset<8> byte4(opt.data_ptr()[4]);
				info->Add("dualbeacon", byte4[6]);
				info->Add("dualcts", byte4[7]);
				bitset<8> byte5(opt.data_ptr()[5]);
				info->Add("secondarybeacon", byte5[0]);
				info->Add("lsigprotsupport", byte5[1]);
				JSONObject * pco = new JSONObject();
				pco->Add("active", byte5[2]);
				pco->Add("phase", byte5[3]);
				info->Add("reserved3", opt.data_ptr()[5] / 16);
				
				// RX Supported Modulation and Coding Scheme Set
				JSONObject * mcsset = ParseMCSSet(opt.data_ptr(), len, 6);

				if (!mcsset) {
					mcsset = new JSONObject();
					mcsset->Add("failed", "MCS Set parsing failure, report this frame.");
				}
				mcsset->Add("tag", optNr);
				mcssetVector.push_back(mcsset);
				//ht->Add("mcsset", mcsset);
				info->Add("pco", pco);
				ht->Add("info", info);
				break;
			}
			case IE_EXTENDED_CAPA:
			{
				tag->Add("name", string("Extended capabilities"));
				if (len == 1) {
					bitset<8> ecTemp(opt.data_ptr()[0]);
					JSONObject * extcap = new JSONObject();
					
					// The 'b' are wireshark tags, not very descriptive
					
					extcap->Add("b0", ecTemp[0]); // 20/40 Coexistence Management support?
					extcap->Add("20_40_coex_mgt", ecTemp[0]); // 20/40 Coexistence Management support?
					extcap->Add("b1", ecTemp[1]); // On-demand beacon support?
					extcap->Add("on_demand_beacon", ecTemp[1]); // On-demand beacon support?
					extcap->Add("b2", ecTemp[2]); // Extended channel switching?
					extcap->Add("ext_chan_switch", ecTemp[2]); // Extended channel switching?
					extcap->Add("b3", ecTemp[3]); // WAVE indication?
					extcap->Add("wave_indication", ecTemp[3]); // WAVE indication?
					extcap->Add("b4", ecTemp[4]); // Power Save Multi-Poll capability?
					extcap->Add("psmp_capa", ecTemp[4]); // Power Save Multi-Poll capability?
					extcap->Add("b5", ecTemp[5]); // Reserved
					extcap->Add("b6", ecTemp[6]); // Scheduled-PSMP Support?
					extcap->Add("spsmp", ecTemp[6]); // Scheduled-PSMP Support?
					extcap->Add("b7", ecTemp[7]); // Event support?
					extcap->Add("event", ecTemp[7]); // Event support?
					
					// PSMP and S-PSMP: https://www.cwnp.com/power-save-multi-poll-psmp/
					wlan_mgt->Add("extcap", extcap);
				}
				break;
			}
			case IE_UPID:
			{
				/* Quoting IEEE document: "A STA can use the U-PID element transmitted in ADDTS Request, 
				 *  DMG ADDTS Request, ADDTS Response and DMG ADDTS Response frames to indicate the
				 *  protocol responsible for handling MSDUs corresponding to the TID indicated within
				 *  the frame carrying the U-PID element (see 11.4.4.4 (TS setup procedures for both AP
				 *  and non-AP STA initiation))."
				 */
				tag->Add("name", string("U-PID"));
				// See wpa-psk-linksys.pcap from aircrack-ng (frame 9)
				break;
			}
			case IE_VENDOR:
			{
				if (len < 4) {
					tag->Add("invalid", string("too short, expected at least 4 bytes long"));
					break;
				}
				JSONObject * vendor = new JSONObject();
				JSONObject * oui = new JSONObject();
				uint8_t vendor_type = opt.data_ptr()[3];
				oui->Add("type", vendor_type);


				uint8_t OUI[3] = {opt.data_ptr()[0], opt.data_ptr()[1], opt.data_ptr()[2] };
				// flawfinder: ignore
				char OUIStr[9] = { 0 };
				snprintf(OUIStr, sizeof(OUIStr), "%02x-%02x-%02x", OUI[0], OUI[1], OUI[2]);

				tag->Add("oui", (OUI[0] * 65536) + (OUI[1] * 256) + OUI[2]);
				tag->Add("oui_parsed", string(OUIStr));

				if (OUI[0] == 0) {
					if (OUI[1] == 0x10 && OUI[2] == 0x18) {
						// Broadcom
						vendor->Add("name", "Broadcom");
						char * data = new char[(len - 4)*3];
						for (unsigned short i = 4; i < len; ++i) {
							snprintf(data + ((i-4)*3), 3, "%2x:", opt.data_ptr()[i]);
						}
						data[((len - 4)*3) - 1] = 0;
						vendor->Add("data", string(data));
						delete[] data;
					} else if (OUI[1] == 0x50 && OUI[2] == 0xf2) {
						// Microsoft
						vendor->Add("name", "Microsoft");
						switch(vendor_type) {
							case 1:
								// WPA Information Element
								oui->Add("type_parsed", string("WPA Information Element"));
								break;
							case 2:
							{
								// WMM/WME
								oui->Add("type_parsed", string("WMM/WME"));
								if (len < 8) {
									oui->Add("invalid", string("Expected 8+ bytes"));
									break;
								}
								JSONObject * wfa = new JSONObject();
								JSONObject * ie = new JSONObject();
								ie->Add("type", vendor_type);
								JSONObject * wme = new JSONObject();
								wme->Add("subtype", opt.data_ptr()[4]);
								wme->Add("version", opt.data_ptr()[5]);
								JSONObject * qos_info = new JSONObject();
								JSONObject * ap = new JSONObject();
								bitset<8> byte6(opt.data_ptr()[6]);
								ap->Add("u_apsd", byte6[7]);
								ap->Add("parameter_set_count", opt.data_ptr()[6] % 16);
								ap->Add("reserved", byte6[4] + (byte6[5] * 2) + (byte6[6] * 4));
								
								wme->Add("reserved", opt.data_ptr()[7]);
								
								JSONObject * acp = NULL;
								if (len > 8 && len % 4 == 0) {
									// Parse AC parameters
									acp = new JSONObject();
									vector<JSONObject *> acpVector;
									for (unsigned short int i = 8; i + 4 <= len; i += 4) {
										JSONObject * acpItem = new JSONObject();
										
										acpItem->Add("aci_aifsn", opt.data_ptr()[i]);
										
										bitset<8> byteBs(opt.data_ptr()[i]);
										acpItem->Add("aci", byteBs[5] + (byteBs[6] * 2));
										acpItem->Add("acm", byteBs[4]);
										acpItem->Add("aifsn", opt.data_ptr()[i] % 16);
										acpItem->Add("reserver", (byteBs[4]));
										
										JSONObject * ecw = new JSONObject();
										ecw->Add("min", opt.data_ptr()[i + 1] % 16);
										ecw->Add("max", opt.data_ptr()[i + 1] / 16);
										ecw->Add("value", opt.data_ptr()[i + 1]);
										
										acpItem->Add("txop_limit", (opt.data_ptr()[i + 3] * 256) + opt.data_ptr()[i + 2]);
										
										acpItem->Add("ecw", ecw);
										acpVector.push_back(acpItem);
									}
									acp->Add("acp", acpVector);
								} else {
									oui->Add("invalid", string("Expected an amount of bytes divisible by 4 - Failed parsing AC Parameters"));
								}

								// Link them together
								qos_info->Add("ap", ap);
								wme->Add("qos_info", qos_info);
								if (acp) {
									wme->Add("acp", acp);
								}
								ie->Add("wme", wme);
								wfa->Add("ie", ie);
								wlan_mgt->Add("wfa", wfa);
								break;
							}
							default:
								break;
						}
					} else if (OUI[1] == 0x0c && OUI[2] == 0x43) {
						// RalinkTe
						vendor->Add("name", "RalinkTe");
						if (len != 7) {
							vendor->Add("invalid", "length: expected 7");
							break;
						}

						// Add vendor data
						// flawfinder: ignore
						char rt[9] = { 0 };
						snprintf(rt, sizeof(rt), "%02x%02x%02x%02x", opt.data_ptr()[3], opt.data_ptr()[4], opt.data_ptr()[5], opt.data_ptr()[6]);
						rt[8] = 0;
						vendor->Add("data", rt);
					} else if (OUI[1] == 0x90 && OUI[2] == 0x4c) {
						// Epigram
						vendor->Add("name", "Epigram");
						switch (vendor_type) {
							case 51:
								// HT Capabilities (802.11n D1.10)
								oui->Add("type_parsed", string("HT Capabilities (802.11n D1.10)"));
								// Same as IE 45, just a different offset for the data
								// What we'll do here is call a function to parse IE 45: JSONObject * parseIE45(JSONObject * ht)
								// (if ht is NULL, we create a new object and return it, if ht is not null, we append to it and return it)
								// NULL is returned if failed 
								break;
							case 52:
								// WMM/WME
								oui->Add("type_parsed", string("HT Additional Capabilities (802.11n D1.00)"));
								break;
							default:
								break;
						}
					} else if (OUI[1] == 0x03 && OUI[2] == 0x7f) {
						// AtherosC
						vendor->Add("name", "AtherosC");
						if (len < 6) {
							tag->Add("invalid", "Expected length of at least 6 bytes");
						}
						JSONObject * atheros = new JSONObject();
						JSONObject * ie = new JSONObject();
						ie->Add("type", vendor_type);
						ie->Add("subtype", opt.data_ptr()[4]);
						ie->Add("version", opt.data_ptr()[5]);
						
						// Make this a define
						char * data = new char[(len - 4)*3];
						for (unsigned short i = 4; i < len; ++i) {
							snprintf(data + ((i-4)*3), 3, "%2x:", opt.data_ptr()[i]);
						}
						data[((len - 4)*3) - 1] = 0;
						ie->Add("data", string(data));
						delete[] data;
						
						// Link them
						atheros->Add("ie", ie);
						wlan_mgt->Add("atheros", atheros);
					} else if (OUI[1] == 0x13 && OUI[2] == 0x92) {
						// Ruckus Wireless
						vendor->Add("name", "RuckusWi");
						if (len == 8) {
							// Add vendor data
							// flawfinder: ignore
							char rw[11] = { 0 };
							snprintf(rw, sizeof(rw), "%02x%02x%02x%02x%02x", opt.data_ptr()[3], opt.data_ptr()[4], opt.data_ptr()[5], opt.data_ptr()[6], opt.data_ptr()[7]);
							rw[10] = 0;
							vendor->Add("data", rw);
						}
					}
				}
				// Resolve manufacturer from /usr/share/wireshark/manuf
				// Required package: libwireshark-data
				// Note: manuf may not be present in Ubuntu 24.04 package anymore

				// In any case have a few MACs known (Microsoft, broadcom, Epigram, RalinkTe)
				// Check out among other things: Chinese-SSID-Name.pcap from Aircrack-ng
				// Vendor specific, need to get vendor based on OUI
				// Create a map with the 3 bytes of the MAC plus the one byte vendor-specific
				// and convert to an unsigned int (manual conversion, *256).
				// Also try with captures from Wireshark Wiki:
				//  https://wiki.wireshark.org/SampleCaptures#Wifi_.2F_Wireless_LAN_captures_.2F_802.11
				
				vendor->Add("oui", oui);
				tag->Add("vendor", vendor);
				break;
			}
			default:
			{
				tag->Add("unknown", string("please report this frame"));
				break;
			}
		}

		optionsVector.push_back(tag);
	}

	// This special one is used in more than one IE
	if (ht) {
		// Add MCS Sets
		if (mcssetVector.size() != 0) {
			ht->Add("mcsset", mcssetVector);
		}

		// Add HT
		wlan_mgt->Add("ht", ht);
	}
	wlan_mgt->Add("tagged", optionsVector);
	return true;
}

JSONObject * wifibeat::utils::tins::ParseMCSSet(const uint8_t* data_ptr, unsigned int len, unsigned int offset)
{
	if (len - offset < 13 + 3) { // 3 bytes padding
		LOG_ERROR("Failed parsing MCS Set, invalid length. Got " + std::to_string(len - offset) + ", expected 15");
		return NULL;
	}
	JSONObject * mcsset = new JSONObject();
	
	// RX Bit mask
	JSONObject * rxbitmask = new JSONObject();
	rxbitmask->Add("0to7", data_ptr[offset]);
	rxbitmask->Add("8to15", data_ptr[offset + 1]);
	rxbitmask->Add("16to23", data_ptr[offset + 2]);
	rxbitmask->Add("24to31", data_ptr[offset + 3]);
	
	// Assuming the amount of streams is based on the number of bytes set to 0xff (up to 4).
	// 1 bit per modulation (MCS)
	unsigned int stream_amount = (data_ptr[offset] + data_ptr[offset + 1] + data_ptr[offset + 2] + data_ptr[offset + 3]) / 0xff;
	rxbitmask->Add("stream_amount", stream_amount);
	
	// Second part
	bitset<8> byte7(data_ptr[offset + 4]);
	rxbitmask->Add("32", (unsigned int)byte7[0]);
	rxbitmask->Add("33to38", (data_ptr[offset + 4] % 128)/2); // Correct
	rxbitmask->Add("39to52", byte7[offset + 4] + ((data_ptr[offset + 5]) * 2) + ((data_ptr[offset + 6] % 32) * 512));
	unsigned long long int b53to76 = (byte7[7] * 2) + (byte7[6] * 2) + byte7[5];
	b53to76 += (data_ptr[offset + 6] / 32) + (data_ptr[offset + 7] * 8) + (data_ptr[offset + 8] * 2048) + ((data_ptr[offset + 9] % 32) * 524288);
	rxbitmask->Add("53to76", b53to76);
	mcsset->Add("rxbitmask", rxbitmask);
	
	unsigned int highestdatarate = data_ptr[offset + 10] + ((data_ptr[offset + 11] % 4) * 256);
	mcsset->Add("highestdatarate", highestdatarate);
	
	bitset<8> byte15(data_ptr[offset + 12]);
	mcsset->Add("txsetdefined", byte15[0]);
	mcsset->Add("txrxmcsnotequal", byte15[1]);
	mcsset->Add("txmaxss", (byte15[3] * 2) + byte15[2]);
	mcsset->Add("txunequalmod", byte15[4]);
	
	return mcsset;
}

JSONObject * wifibeat::utils::tins::ParseRSNInformationCipherSuite(RSNInformation::CypherSuites suite)
{
	JSONObject * gcs = new JSONObject();

	// OUI
	unsigned int oui = (((0x00 * 256) + 0x0f) * 256) + 0xac;
	gcs->Add("oui", oui); // 00-0f-ac, always

	// Display suite
	switch(suite) {
		case RSNInformation::CypherSuites::WEP_40:
			gcs->Add("type", 1ULL);
			gcs->Add("value", (oui * 256) + 1);
			gcs->Add("value_parsed", string("WEP40"));
			break;
		case RSNInformation::CypherSuites::TKIP:
			gcs->Add("type", 2ULL);
			gcs->Add("value", (oui * 256) + 2);
			gcs->Add("value_parsed", string("TKIP"));
			break;
		case RSNInformation::CypherSuites::CCMP:
			gcs->Add("type", 4ULL);
			gcs->Add("value", (oui * 256) + 4);
			gcs->Add("value_parsed", string("CCM"));
			break;
		case RSNInformation::CypherSuites::WEP_104:
			gcs->Add("type", 5ULL);
			gcs->Add("value", (oui * 256) + 5);
			gcs->Add("value_parsed", string("WEP104"));
			break;
		default:
			gcs->Add("type", string("unknown"));
			break;
		
	}

	return gcs;
}

JSONObject * wifibeat::utils::tins::Dot11Control2String(const Dot11Control * frame)
{
	if (frame == NULL) {
		return NULL;
	}
	JSONObject * ret = new JSONObject();

	return ret;
}

wifibeat::utils::tins::Dot11DataObjects * wifibeat::utils::tins::Dot11Data2String(const Dot11Data * frame)
{
	if (frame == NULL) {
		return NULL;
	}
	Dot11DataObjects * ret = new Dot11DataObjects();
	
	const Dot11QoSData * qosFrame = frame->find_pdu<Dot11QoSData>();
	if (qosFrame) {
		// TODO: Add QoS parsing in libtins
		ret->QoS = new JSONObject();
		bitset<16> qosBs(qosFrame->qos_control());
		unsigned int tid = (qosBs[2] * 8) + (qosBs[2] * 4) + (qosBs[1] * 2) + qosBs[0];
		ret->QoS->Add("tid", tid);
		ret->QoS->Add("priority", tid % 8); // First 3 bytes
		ret->QoS->Add("ack", ((qosBs[6] * 2) + qosBs[5]));
		ret->QoS->Add("amsdupresent", qosBs[7]);
		if (frame->from_ds()) {
			ret->QoS->Add("eosp", qosBs[4]);
			ret->QoS->Add("ps_buf_state", (qosFrame->qos_control() / 16)); // Last 8 bytes
			ret->QoS->Add("buf_state_indicated", qosBs[7]);
		} else { //if (frame->to_ds()) {
			ret->QoS->Add("bit4", qosBs[4]);
			ret->QoS->Add("txop_dur_request", (qosFrame->qos_control() / 16)); // Last 8 bytes
		}
	}

	// If privacy is enabled, we got at least 4 bytes after the sequence number
	// or 4th address (if tods and fromdos are set).
	// If it's a QoS frame, there are 2 more bytes after the 4th address and sequence
	// number (see wpa-eat-tls.pcap.gz from Wireshark samples)
	// the 4th byte indicates the type of encryption: if 0 (< 4), it is WEP,
	// if 20, WPA PTK, if 60, WPA GTK (TKIP or CCMP)
	// If WEP, first 3 bytes is the IV, 4th is key number. ICV is at the end of the packet
	// If WPA, we got 4 more bytes, first byte is the IV
	// This might be useful: https://www.wireshark.org/lists/ethereal-dev/200407/msg00066.html

	// See how libtins decrypt
	
	// TODO: Add getting the information above in libtins -> would simplify decryption.
	//frame->inner_pdu()->serialize()

	return ret;
}
