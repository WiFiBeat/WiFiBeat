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
// Decryption will do reordering but at a cost: a small delay,
// so we can have the packets ordered.
// Functioning: take all the packets in the queue and put them on
// a temporary queue.
// When it reaches 30 packets (or more), order them all and put all
// that on an sorted queue.
// Get the first 2/3 or (all minus 20), whichever is greater and
// run decryption on them.
// Another thing: to improve stuff, anything not matching all the 
// BSSID we have keys for, just pass it through.

// We'll need to fine tune this technique. Such as add time based stuff
//  (like if we haven't received anything in the last second, we can
//   assume we have all packets and we can run ordering+decryption on
//   most of them).

// For now: assume we get them in order, this is complicated and needs more thoughts
#ifndef THREAD_DECRYPTION_H
#define THREAD_DECRYPTION_H

#include "ThreadWithQueue.h"
#include "PacketTimestamp.h"
#include "config/decryptionKeys.h"
#include <tins/crypto.h>
#include <vector>

using std::vector;

namespace wifibeat
{
	namespace threads
	{
		class decryption : public ThreadWithQueue<PacketTimestamp>
		{
			private:
				bool _passthrough;
				vector<decryptionKey> _decryptionKeys;
				Tins::Crypto::WPA2Decrypter _decrypter;

			public:
				explicit decryption(const vector<decryptionKey> & decryptionKeys);
				~decryption();
				virtual string toString();
				virtual void recurring();
				virtual bool init_function();

		};

	}

}

#endif // THREAD_DECRYPTION_H
