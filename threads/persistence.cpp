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
#include "persistence.h"
#include "utils/logger.h"
#include <queue>

using std::queue;

/*
persistence: add path in config

persistence: add function in thread to delete item -> referenced by its pointer -> wouldn't work since split
		-> Add uuid (apt-get install uuid-dev)
		http://graemehill.ca/minimalist-cross-platform-uuid-guid-generation-in-c++/

So, we need to add a field in the PacketTimestamp for uuid. However, this will only be added
in the persistence thread, so the end thread can notify packet is no longer needed

Regarding multiple destinations. As long as one persists it, it's fine. But technically, we should have
persistence in the output threads too.

What can be done is:
- persistence at capture time which is handled by persistence thread
- persistence at decryption time (which call the persistence thread to notify it's taking care of it)
  - it takes note of the different pointers which are symlinks to the original one pointer + hash)
- persistence at each output

Need to discuss this issue, issue is complex

Something that can be done is merging persistence in decryption into processing
which would do persistence too.
*/

wifibeat::threads::persistence::persistence()
{
	this->Name("persistence");
}

wifibeat::threads::persistence::~persistence()
{
}

void wifibeat::threads::persistence::recurring()
{
	queue<PacketTimestamp *> q = this->getAllItemsFromInputQueue();
	while (!q.empty()) {
		PacketTimestamp * item = q.front();
		if (item != NULL) { // Should never be null be better be safe than soory
			this->sendToNextThreadsQueue(item);
		}
		q.pop();
	}
}

bool wifibeat::threads::persistence::init_function()
{
	LOG_NOTICE("Persistence thread is set to passthrough for now!");
	return true;
}