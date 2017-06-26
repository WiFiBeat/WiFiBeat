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
#include "hopper.h"
#include "utils/wifi.h"
#include "utils/logger.h"
#include "config/configstructs.h"
#include <net/if.h>
#include <sstream>

// TODO: Integrate horst

using std::stringstream;

wifibeat::threads::hopper::hopper(const string & interface, const vector <channelSetting> & channels)
	: _nl_sock(NULL), _nl_cache(NULL), _nl80211(NULL), _deviceID(0), _position(0),
		_sleep_time(0), _interface(interface), _channels(channels)
{
	this->Name("hopper");
}

wifibeat::threads::hopper::~hopper()
{
	this->freeLibnl80211();
}

bool wifibeat::threads::hopper::initLibnl80211()
{
	this->_nl_sock = nl_socket_alloc();
	if (!this->_nl_sock) {
		LOG_ERROR("Failed to allocate netlink socket");
		return false;
	}

	if (genl_connect(this->_nl_sock)) {
		LOG_ERROR("Failed to connect to generic netlink");
		this->freeLibnl80211();
		return false;
	}

	if (genl_ctrl_alloc_cache(this->_nl_sock, &this->_nl_cache)) {
		LOG_ERROR("Failed to allocate generic netlink cache");
		this->freeLibnl80211();
		return false;
	}

	this->_nl80211 = genl_ctrl_search_by_name(this->_nl_cache, "nl80211");
	if (!this->_nl80211) {
		LOG_CRITICAL("nl80211 not found");
		this->freeLibnl80211();
		return false;
	}

	LOG_NOTICE("Initialized libnl80211 successfully");

	return true;
}

void wifibeat::threads::hopper::freeLibnl80211()
{
	if (this->_nl80211) {
		genl_family_put(this->_nl80211);
	}
	if (this->_nl_cache) {
		nl_cache_free(this->_nl_cache);
	}
	if (this->_nl_sock) {
		nl_socket_free(this->_nl_sock);
	}
}

bool wifibeat::threads::hopper::setChannel(const channelSetting & channel)
{
	struct nl_msg *msg;
	unsigned int freq;
	int htval = NL80211_CHAN_NO_HT;

	LOG_DEBUG("Setting channel " + std::to_string(channel.channel) + " on " + this->_interface);

	// Convert channel to frequency
	freq = this->_chan2freq[channel.channel];
	if (freq < 1) {
		stringstream ss;
		ss << "Invalid frequency for channel " << channel.channel;
		LOG_WARN(ss.str());
		return false;
	}

	// Allocate memory
	msg = nlmsg_alloc();
	if (!msg) {
		LOG_CRITICAL("Failed allocating memory for NL80211 message");
		return false;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(this->_nl80211), 0,
				0, NL80211_CMD_SET_WIPHY, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, this->_deviceID);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

	// Set HT mode
	switch (channel.htMode) {
		case HT20:
			htval = NL80211_CHAN_HT20;
			break;
		case HT40_MINUS:
			htval = NL80211_CHAN_HT40MINUS;
			break;
		case HT40_PLUS:
			htval = NL80211_CHAN_HT40PLUS;
			break;
		default:
			htval = NL80211_CHAN_NO_HT;
			break;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, htval);
	nl_send_auto_complete(this->_nl_sock, msg);
	nlmsg_free(msg);

	// Update sleep time
	this->_sleep_time = this->_channels[this->_position].time;

	// Go to the next position
	++(this->_position);
	if (this->_position == this->_channels.size()) {
		this->_position = 0;
	}

	// nla_put_failure:
	if (0) {
nla_put_failure:
		LOG_ERROR("setChannel(): nla_put_failure error");
		return false;
	}

	return true;
}

void wifibeat::threads::hopper::recurring()
{
	// If only one channel, don't do anything
	if (this->_channels.size() == 1) {
		return;
	}

	// Wait before changing channel
	if (this->_sleep_time > 0) {
		--(this->_sleep_time);
		return;
	}

	// Change channel
	this->setChannel(this->_channels[this->_position]);
}

bool wifibeat::threads::hopper::init_function()
{
	if (this->_interface.empty() || this->_channels.empty()) {
		return false;
	}

	// Get device id (saves some time in processing)
	stringstream ss;
	this->_deviceID = if_nametoindex(this->_interface.c_str());
	if (this->_deviceID == 0) {
		ss << "Interface <" << this->_interface << "> does not exists";
		LOG_ERROR(ss.str());
		return false;
	}

	// Initialize libnl
	if (!this->initLibnl80211()) {
		LOG_ERROR("Failed initializing libnl80211");
		return false;
	}

	// TODO: Validate channels -> make sure the card is allowed on those channels
	//       A "bad" way to do it might be to make it change to all those channels

	// Convert all channels to frequencies (saves some time in processing)
	for (const channelSetting & cs: this->_channels) {
		if (!_chan2freq.count(cs.channel)) {
			_chan2freq.insert({cs.channel, wifibeat::utils::wifi::channel2frequency(cs.channel)});
		}
	}

	// Set the card on the first channel (and increment position)
	if (!this->setChannel(this->_channels[0])) {
		ss << "Failed setting channel on <" << this->_interface << "> to " << this->_channels[0].channel;
		LOG_ERROR(ss.str());
		return false;
	}

	return true;
}

string wifibeat::threads::hopper::toString()
{
	std::stringstream ss;
	ss << this->Name() << " (" << this->_interface << "): ";
	if (this->_channels.size() == 0) {
		ss << "No channel set!";
		return ss.str();
	}

	if (this->_channels.size() > 1) {
		ss << "[ ";
	}
	
	bool first = true;
	for (const channelSetting & cs: this->_channels) {
		if (first) {
			first = false;
		} else {
			ss << ", ";
		}
		ss << cs.channel;
		if (this->_channels.size() != 1) {
			ss << " for " << cs.time << "ms";
		}
		if (cs.htMode != NO_HT) {
			ss << " (HT mode: ";
			switch (cs.htMode) {
				case NO_HT:
					// Avoid using -Wswitch
					break;
				case HT20:
					ss << "HT20)";
					break;
				case HT40_MINUS:
					ss << "HT40-)";
					break;
				case HT40_PLUS:
					ss << "HT40+)";
					break;
			}
		}
	}

	if (this->_channels.size() > 1) {
		ss << " ]";
	}

	return ss.str();
}