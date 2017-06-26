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
#ifndef THREADMANAGER_H
#define THREADMANAGER_H

#include "threads/capture.h"
#include "threads/decryption.h"
#include "threads/elasticsearch.h"
#include "threads/filereading.h"
#include "threads/hopper.h"
#include "threads/logstash.h"
#include "threads/persistence.h"
#include "threads/filewriting.h"
#include <pthread.h>


namespace wifibeat
{
	class threadManager
	{
		private:
			vector<threads::hopper *> _hoppers;
			vector<threads::capture *> _captures;
			vector<threads::filereading *> _filereadings;
			vector<threads::elasticsearch *> _elasticsearches;
			vector<threads::logstash *> _logstashes;
			threads::decryption * _decryption;
			threads::persistence * _persistence;
			vector<threads::filewriting *> _filewriters;

			pthread_mutex_t _mutex;
			bool _mutexInit;

			void stopWait(ThreadWithQueue <PacketTimestamp> * thread, bool waitForQueueToEmpty = false);

		public:
			threadManager(const string & pcapPrefix);
			~threadManager();
			bool start();
			bool stop();
			bool init();
			bool canStop();
	};

}

#endif // THREADMANAGER_H
