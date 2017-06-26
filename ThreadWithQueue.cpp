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
#include "ThreadWithQueue.h"
#include "utils/Locker.h"
#include "utils/logger.h"
#include <signal.h>

using wifibeat::utils::Locker;

template <class T>
inline string wifibeat::ThreadWithQueue<T>::Name() {
	return this->_name;
}

template <class T>
inline void wifibeat::ThreadWithQueue<T>::Name(const string & name) {
	this->_name = name;
	LOG_NOTICE("Set thread's name to <" + name + ">");
}

template <class T>
inline wifibeat::threadStatus wifibeat::ThreadWithQueue<T>::Status() {
	Locker l(&this->_statusMutex); 
	return this->_status;
}

template <class T>
std::queue <T *> wifibeat::ThreadWithQueue<T>::getAllItemsFromInputQueue() {
	T * item = NULL;
	queue<T *> in_queue;
	while (!this->_inputQueue.empty()) {
		this->_inputQueue.pop(item);
		in_queue.push(item);
	}

	return in_queue;
}

template <class T>
inline void wifibeat::ThreadWithQueue<T>::Status(wifibeat::threadStatus newStatus) {
	Locker l(&this->_statusMutex);
	this->_status = newStatus;
}

template <class T>
bool wifibeat::ThreadWithQueue<T>::allQueuesEmpty() {
	
	return this->_inputQueue.empty();
}

// Default function if no init is needed.
template <class T>
bool wifibeat::ThreadWithQueue<T>::init_function() {
	return true;
}

template <class T>
bool wifibeat::ThreadWithQueue<T>::init(const unsigned long long int ns) {
	switch(this->Status()) {
			case Created:
			case InitializationFailed:
			case StartingFailed:
			case Stopped:
			case Crashed:
			case Aborted:
			case Killed:
				// Status where it can be initialized (again)
				break;
			default:
				// In any other case, no touching
				return false;
	}

	this->Status(Initializing);

	// Set-up sleep time
	if (ns == 0) {
		this->_loopSleepTimeNS = NULL;
	} else {
		this->_loopSleepTimeNS = new std::chrono::nanoseconds(ns); // Or maybe {}
	}

	if (init_function() == false) {
		this->Status(InitializationFailed);
		LOG_ERROR("Failed initializing <" + this->Name() + "> thread");
		return false;
	}

	this->Status(Initialized);
	LOG_NOTICE("Initialized <" + this->Name() + "> thread");

	return true;
}

template <class T>
bool wifibeat::ThreadWithQueue<T>::addItemToInputQueue(T * item) {
	if (item == NULL) {
		return false;
	}
	return this->_inputQueue.push(item);
}

template <class T>
bool wifibeat::ThreadWithQueue<T>::start() {
	Locker l(&this->_threadMutex); // Prevent accessing thread multiple times
	switch (this->Status()) {
		case Initialized:
		case Stopped:
		case Crashed:
		case Aborted:
		case Killed:
			// We can keep going
			break;
		default:
			return false;
	}

	this->Status(Starting);

	try {
		this->_thread = new std::thread(&ThreadWithQueue<T>::_loop, this);
		this->_thread->detach();
	} catch (...) {
		this->Status(StartingFailed);
		LOG_ERROR("Failed creating <" + this->Name() + "> thread");
		return false;
	}

	LOG_DEBUG("Created thread <" + this->Name() + ">");

	return true;
}

template <class T>
void wifibeat::ThreadWithQueue<T>::_loop() {
	this->Status(Started);
	LOG_DEBUG("Thread <" + this->Name() + "> started");

	// Block SIGINT and SIGTERM that are handled by the parents.
	sigset_t signal_set;
	sigemptyset(&signal_set);
	sigaddset(&signal_set, SIGINT);
	sigaddset(&signal_set, SIGTERM);
	if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0) {
		this->Status(Crashed);
		return;
	}

	this->Status(Running);
	LOG_DEBUG("Thread <" + this->Name() + "> running");

	// Do loop
	// Conditions: Either running or stopping, this->_stopWaitQueueIsEmpty and queue not empty
	threadStatus ts = this->Status();
	while (ts == Running || (this->_stopWaitQueueIsEmpty && ts == Stopping && !this->allQueuesEmpty())) {

		try {
			// Run the recurring function
			this->recurring();

			// Sleep a bit
			if (this->_loopSleepTimeNS != NULL) {
				std::this_thread::sleep_for(*(this->_loopSleepTimeNS));
			}
		} catch (...) {
			this->Status(Crashed);
			LOG_ERROR("Thread <" + this->Name() + "> crashed");
			return;
		}

		ts = this->Status();
	}

	// Empty queue
	T * item = NULL;
	while (!this->_inputQueue.empty()) {
		this->_inputQueue.pop(item);
		delete item;
	}
	this->Status(Stopped);
	LOG_DEBUG("Thread <" + this->Name() + "> stopped");
}

template <class T>
inline void wifibeat::ThreadWithQueue<T>::ThreadFinished() {
	if (this->stop(false)) {
		LOG_NOTICE("Thread <" + this->Name() + "> is finished and will stop");
	} else {
		LOG_ERROR("Thread <" + this->Name() + "> has failed being stopped, invalid status!");
	}
}

template <class T>
bool wifibeat::ThreadWithQueue<T>::stop(bool waitQueueIsEmpty) {
	if (this->Status() != Running) {
		return false;
	}

	this->_stopWaitQueueIsEmpty = waitQueueIsEmpty;
	this->Status(Stopping);

	return true;
}


template <class T>
bool wifibeat::ThreadWithQueue<T>::kill(unsigned int ms) {
	Locker l(&this->_threadMutex); // Prevent accessing thread multiple times
	if (this->_thread == NULL) {
		return true;
	}

	threadStatus ts = this->Status();
	if (ts == Running) {
		// stop() needs to be called first!
		return false;
	}

	if (ts != Stopped) { 
		LOG_NOTICE("Thread <" + this->Name() + "> will be killed soon! Muahahaha");

		// Wait a little while (if requested before killing/joing them)
		while (ms > 0 && this->Status() == Stopping) {
			if (ms < 10) {
				std::this_thread::sleep_for(std::chrono::milliseconds(ms));
				break;
			} 
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			ms -= 10;
		}
	}
	
	// Now kill it
	delete this->_thread;
	this->_thread = NULL;
	if (ts != Stopped) {
		this->Status(Killed);
	}

	return true;
}

// Virtual output queue stuff
template <class T>
bool wifibeat::ThreadWithQueue<T>::sendToNextThreadsQueue(T * item) {
	if (item == NULL) {
		return false;
	}
	bool success = true;
	switch (this->_nextThreads.size()) {
		case 0:
			success = false;
			break;
		case 1:
			success = this->_nextThreads[0]->addItemToInputQueue(item);
			break;
		default:
			// Minimize allocations in case one instance fails
			T * itemCopy = NULL;
			for (unsigned int i = 1; success && i < this->_nextThreads.size(); ++i) {
				// Send a copy to all other threads
				if (itemCopy == NULL) {
					itemCopy = new T(*item);
				}
				success = false;
				if (itemCopy != NULL && this->_nextThreads[0]->addItemToInputQueue(itemCopy)) {
					success = true;
					itemCopy = NULL;
				}
			}
			if (itemCopy) {
				delete itemCopy;
			}
			
			// Now send the original
			if (success) {
				success = this->_nextThreads[0]->addItemToInputQueue(item);
			}
			break;
	}


	// Destroy item if failure.
	if (!success) {
		delete item;
		item = NULL;
	}

	return success;
}

template <class T>
inline bool wifibeat::ThreadWithQueue<T>::AddNextThread(ThreadWithQueue * nextThread) {
	if (nextThread == NULL) {
		return false;
	}
	this->_nextThreads.push_back(nextThread);
	return true;
}

// End of output queue

template <class T>
wifibeat::ThreadWithQueue<T>::ThreadWithQueue()
	: _threadMutexInit(false), _name(""), _thread(NULL), _statusMutexInit(false),
		_status(Created), _stopWaitQueueIsEmpty(true), _loopSleepTimeNS(NULL)
{
	if (pthread_mutex_init(&this->_statusMutex, NULL) != 0) {
		LOG_CRITICAL("Failed initializing thread status mutex");
		throw string("Failed initializing thread status mutex");
	}
	this->_statusMutexInit = true;

	if (pthread_mutex_init(&this->_threadMutex, NULL) != 0) {
		LOG_CRITICAL("Failed initializing thread mutex");
		throw string("Failed initializing thread mutex");
	}
	this->_threadMutexInit = true;
}

template <class T>
wifibeat::ThreadWithQueue<T>::~ThreadWithQueue() {

	if (this->_thread != NULL) {
		this->stop();
		this->kill(1000);
	}

	delete this->_loopSleepTimeNS;

	// Empty queue
	T * item = NULL;
	while (!this->_inputQueue.empty()) {
		this->_inputQueue.pop(item);
		delete item;
	}

	// Destroy mutexes
	if (this->_statusMutexInit) {
		pthread_mutex_destroy(&this->_statusMutex);
	}
	if (this->_threadMutexInit) {
		pthread_mutex_destroy(&this->_threadMutex);
	}
}

template <class T>
string wifibeat::ThreadWithQueue<T>::toString()
{
	return this->Name();
}