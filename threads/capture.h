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
#ifndef THREAD_CAPTURE_H
#define THREAD_CAPTURE_H

#include "ThreadWithQueue.h"
#include "PacketTimestamp.h"
#include <tins/sniffer.h>
#include <time.h>

namespace wifibeat
{
	namespace threads
	{
		class capture : public ThreadWithQueue<PacketTimestamp>
		{
			private:
				string _interface;
				string _filter;

				Tins::Sniffer * _sniffer;

				int _pcapFd;
				fd_set _fdSet;
				struct timeval _tv;

				string _string;

			public:
				capture(const string & interface, const string & filter);
				~capture();
				string Interface();

				virtual string toString();
				virtual void recurring();
				virtual bool init_function();
		};

	}

}

#endif // THREAD_CAPTURE_H
