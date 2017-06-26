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
#include "decryption.h"
#include "utils/logger.h"
#include <queue>
#include <sstream>

wifibeat::threads::decryption::decryption(const vector<decryptionKey> & decryptionKeys)
	: _passthrough(false), _decryptionKeys(decryptionKeys)
{
	this->Name("decryption");
}

wifibeat::threads::decryption::~decryption()
{
}

void wifibeat::threads::decryption::recurring()
{
	PacketTimestamp * item = NULL;

	// 1. Get all packets from the input queue
	std::queue<PacketTimestamp *> items = this->getAllItemsFromInputQueue();

	while (!items.empty()) {
		item = items.front();
		items.pop();
		if (item == NULL) {
			continue;
		}

		// Attempt decryption if there are decryption keys
		if (!this->_passthrough) {
			Tins::PDU * pdu = item->getPDU();

			// 2. Attempt decryption
			this->_decrypter.decrypt(*pdu);
		
		}

		// 3. Put the decrypted packet in the queue
		this->sendToNextThreadsQueue(item);
	}
}

bool wifibeat::threads::decryption::init_function()
{
	// Load keys
	for (const decryptionKey & dk: this->_decryptionKeys) {
		if (dk.key.empty() || dk.essid.empty() || dk.bssid.empty()) {
			return false;
		}
		this->_decrypter.add_ap_data (dk.key, dk.essid, dk.bssid);
	}

	// Passthrough if no keys present
	this->_passthrough = this->_decryptionKeys.empty();
	
	if (this->_passthrough) {
		LOG_NOTICE("Decryption set to passthrough, not decrypting anything!");
	}

	return true;
}

string wifibeat::threads::decryption::toString()
{
	std::stringstream ss;
	ss << this->Name() << ": ";
	if (this->_decryptionKeys.empty()) {
		ss << "No keys!";
		return ss.str();
	}

	bool first = true;
	for (const decryptionKey & dk: this->_decryptionKeys) {
		if (first) {
			first = false;
		} else {
			ss << ", ";
		}
		ss << dk.essid << " (BSSID: " << dk.bssid << " - Passphrase: " << dk.key << ")";
	}

	return ss.str();
}
