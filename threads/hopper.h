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
#ifndef THREAD_HOPPER_H
#define THREAD_HOPPER_H

#include "ThreadWithQueue.h"
#include "PacketTimestamp.h"
#include "config/hopping.h"
#include <string>
#include <vector>
#include <map>
#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/genetlink.h>

using std::string;
using std::vector;
using std::map;

namespace wifibeat
{
	namespace threads
	{
		// It actually does not matter what kind of class we use
		// for the thread since we don't need queues
		class hopper : public ThreadWithQueue<PacketTimestamp>
		{
		private:

				// libnl stuff
				struct nl_sock * _nl_sock;
				struct nl_cache * _nl_cache;
				struct genl_family * _nl80211;
				unsigned int _deviceID;

				bool initLibnl80211();
				void freeLibnl80211();

				bool setChannel(const channelSetting & channel);

				unsigned int _position;
				unsigned int _sleep_time;

				string _interface;
				map<unsigned int, int> _chan2freq;
				vector <channelSetting> _channels;
			public:
				hopper(const string & interface, const vector <channelSetting> & channels);
				~hopper();
				virtual string toString();
				virtual void recurring();
				virtual bool init_function();

		};

	}

}

#endif // THREAD_HOPPER_H
