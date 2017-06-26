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
#ifndef THREAD_LOGSTASH_H
#define THREAD_LOGSTASH_H

#include "ThreadWithQueue.h"
#include "PacketTimestamp.h"

namespace wifibeat
{
	namespace threads
	{
		class logstash : public ThreadWithQueue<PacketTimestamp>
		{
			public:
				logstash();
				~logstash();
				virtual void recurring();
				virtual bool init_function();

		};

	}

}

#endif // THREAD_LOGSTASH_H
