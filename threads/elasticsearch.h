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
#ifndef THREAD_ELASTICSEARCH_H
#define THREAD_ELASTICSEARCH_H

#include "ThreadWithQueue.h"
#include "PacketTimestamp.h"
#include "config/es.h"
#include <elasticbeat-cpp/elastic.h>
#include <vector>

#define _WIFIBEAT_ES_INDEX_BASENAME "wifibeat"

using beat::protocols::elastic;
using std::vector;

namespace wifibeat
{
	namespace threads
	{
		class elasticsearch : public ThreadWithQueue<PacketTimestamp>
		{
			private:
				ElasticSearchConnection _settings;
				vector<elastic *> _connections;
				pthread_mutex_t _connectionMutex;
				bool _mutexInit;

			public:
				explicit elasticsearch(const ElasticSearchConnection & connection);
				~elasticsearch();
				virtual string toString();
				virtual void recurring();
				virtual bool init_function();

		};

	}

}

#endif // THREAD_ELASTICSEARCH_H
