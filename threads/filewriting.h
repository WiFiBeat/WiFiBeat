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
#ifndef THREAD_FILEWRITING_H
#define THREAD_FILEWRITING_H

#include <string>
#include <tins/packet_writer.h>
#include <pthread.h>
#include "ThreadWithQueue.h"
#include "PacketTimestamp.h"

using std::string;
using Tins::PacketWriter;

namespace wifibeat
{
	namespace threads
	{
		class filewriting : public ThreadWithQueue<PacketTimestamp>
		{
			private:
				string _string;
				string _interface;
				string _filePrefix;

				string _filename;
				
				pthread_mutex_t _mutex;
				bool _mutexInit;
				PacketWriter * _packet_writer;

			public:
				filewriting(const string & interface, const string & filePrefix);
				~filewriting();
				string Interface();
				
				virtual string toString();
				virtual void recurring();
				virtual bool init_function();

		};

	}

}

#endif // THREAD_FILEWRITING_H
