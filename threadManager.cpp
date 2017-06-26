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
#include "threadManager.h"
#include "config/configuration.h"
#include <sstream>
#include "utils/Locker.h"
#include "utils/logger.h"
#include <pthread.h>

using std::stringstream;

wifibeat::threadManager::threadManager(const string & pcapPrefix) : _decryption(NULL), _persistence(NULL), _mutexInit(false)
{
	if (pthread_mutex_init(&this->_mutex, NULL) != 0) {
		LOG_CRITICAL("Failed initializing Thread Manager mutex");
		throw string("Failed initializing Thread Manager mutex");
    }
	this->_mutexInit = true;
	wifibeat::utils::Locker l(&this->_mutex); // Avoid tsan complaining of race condition

	// Capture files
	for (const string file: configuration::Instance()->filesToRead) {
		LOG_DEBUG("Adding new file to read: " + file);
		threads::filereading * pcap = new threads::filereading(file, "");
		this->_filereadings.push_back(pcap);
	}

	// Ouput PCAP Prefix
	string prefix = "";
	if (configuration::Instance()->PCAPOutput.enabled) {
		prefix = configuration::Instance()->PCAPOutput.prefix;
	}
	// Parameter from console has priority over the item in configuration
	if (pcapPrefix.empty() == false) {
		prefix = pcapPrefix;
	}

	// Capture cards
	for (auto & kv: configuration::Instance()->channelHopping) {
		string filter = "";
		if (configuration::Instance()->interfaceFilters.count(kv.first)) {
			filter = configuration::Instance()->interfaceFilters[kv.first];
		}

		LOG_DEBUG("Adding new live capture: " + kv.first + " (with filter: " + filter + ")" );
		this->_captures.push_back(new threads::capture(kv.first, filter));

		if (prefix.empty() == false) {
			LOG_DEBUG("Adding new File writer for interface <" + kv.first + ">");
			this->_filewriters.push_back(new threads::filewriting(kv.first, prefix));
		}
	}

	// Hopper
	for (auto & kv : configuration::Instance()->channelHopping) {
		LOG_DEBUG("Adding new hopper on " + kv.first);
		threads::hopper * hop = new threads::hopper(kv.first, kv.second);
		this->_hoppers.push_back(hop);
	}

	// Persistence
	LOG_DEBUG("Adding persistence");
	LOG_DEBUG("Note: It will do just passthrough if disabled");
	this->_persistence = new threads::persistence();

	// Decryption
	if (configuration::Instance()->decryptionKeys.size() != 0) {
		// We could create it anyway but that adds some processing time for nothing
		LOG_DEBUG("Adding decryption");
		this->_decryption = new threads::decryption(configuration::Instance()->decryptionKeys);
	}

	// ElasticSearch
	for (const ElasticSearchConnection & conn : configuration::Instance()->ESOutputs) {
		stringstream ss;
		ss << "Adding Elasticsearch output: ";
		for (const IPPort & ipp: conn.hosts) {
			ss << ipp.host << ':' << ipp.port << ' ';
		}
		LOG_DEBUG(ss.str());
		threads::elasticsearch * es = new threads::elasticsearch(conn);
		this->_elasticsearches.push_back(es);
	}

	/*
	// TODO: Logstash
	for (const LogstashConnection & conn : configuration::Instance()->LSOutputs) {
		stringstream ss;
		ss << "Adding Logstash output: ";
		for (const IPPort & ipp: conn.hosts) {
			ss << ipp.host << ':' << ipp.port << ' '
		}
		LOG_DEBUG(ss.str());
		threads::logstash * ls = new threads::logstash();
		this->_logstashes.push_back(ls);
	}
	*/
}

wifibeat::threadManager::~threadManager()
{
	LOG_DEBUG("Deleting thread manager");
	this->stop();

	wifibeat::utils::Locker * l = new wifibeat::utils::Locker(&this->_mutex); // Avoid tsan complaining of race condition
	for (threads::filereading * fr: this->_filereadings) {
		delete fr;
	}
	for (threads::capture * cap: this->_captures) {
		delete cap;
	}
	for (threads::filewriting * fw : this->_filewriters) {
		delete fw;
	}
	for (threads::hopper * hop: this->_hoppers) {
		delete hop;
	}
	delete _decryption;
	for (threads::elasticsearch * es: this->_elasticsearches) {
		delete es;
	}
	for (threads::logstash * ls: this->_logstashes) {
		delete ls;
	}
	delete _persistence;

	delete l;
	if (this->_mutexInit) {
		pthread_mutex_destroy(&this->_mutex);
	}
}

bool wifibeat::threadManager::start()
{
	stringstream ss;
	wifibeat::utils::Locker l(&this->_mutex); // Avoid tsan complaining of race condition

	LOG_DEBUG("threadManager start()");

	// Starting them in reverse order

	// Logstash outputs
	for (threads::logstash * ls: this->_logstashes) {
		if (!ls->start()) {
			ss << "Failed starting " << ls->Name();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Elasticsearch outputs
	for (threads::elasticsearch * es: this->_elasticsearches) {
		if (!es->start()) {
			ss << "Failed starting " << es->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Decryption
	if (this->_decryption && !this->_decryption->start()) {
		LOG_ERROR("Failed starting decryption thread");
		return false;
	}

	// Persistence
	if (!this->_persistence->start()) {
		LOG_ERROR("Failed starting persistence thread");
		return false;
	}

	// Hoppers
	for (threads::hopper * hop: this->_hoppers) {
		if (!hop->start()) {
			ss << "Failed starting " << hop->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// File writing
	for (threads::filewriting * fw: this->_filewriters) {
		if (!fw->start()) {
			ss << "Failed starting " << fw->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Capture threads
	for (threads::capture * cap: this->_captures) {
		if (!cap->start()) {
			ss << "Failed starting " << cap->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Files to read
	for (threads::filereading * fr: this->_filereadings) {
		if (!fr->start()) {
			ss << "Failed initializing " << fr->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	return true;
}

void wifibeat::threadManager::stopWait(ThreadWithQueue <PacketTimestamp> * thread, bool waitForQueueToEmpty)
{
	if (thread == NULL) {
			return;
	}

	thread->stop(waitForQueueToEmpty);

	while (thread != NULL && (thread->Status() == Running || thread->Status() == Stopping)) {
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
}

bool wifibeat::threadManager::stop()
{
	wifibeat::utils::Locker l(&this->_mutex); // Avoid tsan complaining of race condition
	LOG_DEBUG("threadManager stop");

	// Stop all threads cleanly
	for (threads::filereading * fr: this->_filereadings) {
		this->stopWait(fr);
	}
	for (threads::capture * cap: this->_captures) {
		this->stopWait(cap);
	}
	for (threads::filewriting * fw: this->_filewriters) {
		this->stopWait(fw);
	}
	for (threads::hopper * hop: this->_hoppers) {
		this->stopWait(hop);
	}
	this->stopWait(this->_decryption, true);
	for (threads::elasticsearch * es: this->_elasticsearches) {
		this->stopWait(es, true);
	}
	for (threads::logstash * ls: this->_logstashes) {
		this->stopWait(ls, true);
	}
	this->stopWait(this->_persistence, true);
	return true;
}

bool wifibeat::threadManager::init()
{
	stringstream ss;
	wifibeat::utils::Locker l(&this->_mutex); // Avoid tsan complaining of race condition
	// 1. Initialize threads
	LOG_DEBUG("threadManager thread initialization");

	// Files to read
	for (threads::filereading * fr: this->_filereadings) {
		if (!fr->init(1)) {
			ss << "Failed initializing " << fr->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Capture threads
	for (threads::capture * cap: this->_captures) {
		if (!cap->init(1)) {
			ss << "Failed initializing " << cap->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// File writing
	for (threads::filewriting * fw: this->_filewriters) {
		if (!fw->init(100)) {
			ss << "Failed initializing " << fw->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Hoppers
	for (threads::hopper * hop: this->_hoppers) {
		if (!hop->init()) {
			ss << "Failed initializing " << hop->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Persistence
	if (!this->_persistence->init(100)) {
		LOG_ERROR("Failed initializing persistence thread");
		return false;
	}

	// Decryption
	if (this->_decryption && !this->_decryption->init()) {
		LOG_ERROR("Failed initializing decryption thread");
		return false;
	}

	// Elasticsearch outputs
	for (threads::elasticsearch * es: this->_elasticsearches) {
		if (!es->init(100000)) {
			ss << "Failed initializing " << es->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// Logstash outputs
	for (threads::logstash * ls: this->_logstashes) {
		if (!ls->init(100000)) {
			ss << "Failed initializing " << ls->toString();
			LOG_ERROR(ss.str());
			return false;
		}
	}

	// 2. Link them together
	LOG_DEBUG("threadManager: linking all thread's queues together");
	if (this->_filewriters.size() == 0) {
		// Directly linking to persistence
		for (threads::capture * cap: this->_captures) {
			if (!cap->AddNextThread(this->_persistence)) {
				ss << "Failed linking " << cap->toString() << " to persistence thread's queue";
				LOG_ERROR(ss.str());
				return false;
			}
		}
	} else {
		// Linking to filewriting
		for (threads::capture * cap: this->_captures) {
			for (threads::filewriting * fw: this->_filewriters) {
				if (cap->Interface().compare(fw->Interface()) == 0) {
					if (!cap->AddNextThread(fw)) {
						ss << "Failed linking " << cap->toString() << " to <" << fw->toString() << "> queue";
						LOG_ERROR(ss.str());
						return false;
					}
					break;
				}
			}
		}

		// Then linking all filewriting to persistence
		for (threads::filewriting * fw: this->_filewriters) {
			if (!fw->AddNextThread(this->_persistence)) {
				ss << "Failed linking " << fw->toString() << " to persistence thread's queue";
				LOG_ERROR(ss.str());
				return false;
			}
		}
	} 

	// Different depending on if decryption is required
	if (this->_decryption) {
		// Files don't need persistence, they are already on disk
		for (threads::filereading * fr: this->_filereadings) {
			if (!fr->AddNextThread(this->_decryption)) {
				ss << "Failed linking " << fr->toString() << " to decryption thread's queue";
				LOG_ERROR(ss.str());
				return false;
			}
		}

		if (!this->_persistence->AddNextThread(this->_decryption)) {
			LOG_ERROR("Failed linking persistence to decryption thread's queue");
			return false;
		}
		for (threads::elasticsearch * es: this->_elasticsearches) {
			if (!this->_decryption->AddNextThread(es)) {
				ss << "Failed linking " << es->toString() << " to decryption thread's queue";
				LOG_ERROR(ss.str());
				return false;
			}
		}
		for (threads::logstash * ls: this->_logstashes) {
			if (!this->_decryption->AddNextThread(ls)) {
				ss << "Failed linking " << ls->toString() << " to decryption thread's queue";
				LOG_ERROR(ss.str());
				return false;
			}
		}
	} else {
		// No decryption
		for (threads::elasticsearch * es: this->_elasticsearches) {
			// Files don't need persistence, they are already on disk
			for (threads::filereading * fr: this->_filereadings) {
				if (!fr->AddNextThread(es)) {
					ss << "Failed linking " << fr->toString() << " to " << es->toString() << " thread's queue";
					LOG_ERROR(ss.str());
					return false;
				}
			}

			if (!this->_persistence->AddNextThread(es)) {
				ss << "Failed linking persistence to " << es->toString() << " thread's queue";
				LOG_ERROR(ss.str());
				return false;
			}
		}
		for (threads::logstash * ls: this->_logstashes) {
			// Files don't need persistence, they are already on disk
			for (threads::filereading * fr: this->_filereadings) {
				if (!fr->AddNextThread(ls)) {
					ss << "Failed linking " << fr->toString() << " to " << ls->toString() << " thread's queue";
					LOG_ERROR(ss.str());
					return false;
				}
			}

			if (!this->_persistence->AddNextThread(ls)) {
				ss << "Failed linking persistence to " << ls->toString() << " thread's queue";
				LOG_ERROR(ss.str());
				return false;
			}
		}
	}

	return true;
}

bool wifibeat::threadManager::canStop()
{
	// If all capture threads are finished, crashed, killed or aborted, we can stop
	// And all persistence threads
	threadStatus ts;
	wifibeat::utils::Locker l(&this->_mutex); // Avoid tsan complaining of race condition
	for (threads::filereading * fr: this->_filereadings) {
		ts = fr->Status();
		if (ts == Starting || ts == Started || ts == Running) {
			return false;
		}
	}

	for (threads::capture * cap: this->_captures) {
		ts = cap->Status();
		if (ts == Starting || ts == Started || ts == Running) {
			return false;
		}
	}

	// Persistence is a special case and will need a function to check if it can stop
	// We need to make sure all items have been persisted before stopping.
	/*
	if (this->_persistence) {
		ts = this->_persistence->Status();
		if (ts == Starting || ts == Started || ts == Running) {
			return false;
		}
	}
	*/

	return true;
}
