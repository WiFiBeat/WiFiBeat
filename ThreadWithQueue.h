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
#ifndef THREADWITHQUEUE_H
#define THREADWITHQUEUE_H

#include <queue>
#include <thread>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include <boost/lockfree/queue.hpp>

using std::vector;
using std::string;
using std::queue;
using std::thread;

/* 
 * Create new thread: class myThread : ThreadWithQueue<ITEMS_IN_QUEUE> { //class stuff }
 * In the constructor, optionally call setName() to set a name. You might also need to call
 * NextThread() with the next thread's pointer so queues can communicate.
 * 
 * The bare minimum that needs to be implemented is recurring():
 *     * It will need to call getAllItemsFromInputQueue() to obtain all the items in the input queue
 *     * You might need to call sendToNextThreadsQueue(ITEM) to send stuff to the next thread's queue
 * 
 * Optionally, the following can be implemented:
 * - init_function() to initialize the thread. Avoid doing the initialization in the constructor to save time.
 *   Returns true if successful, false if failed.
 * - destructor: cleanup.
 * - toString(): so it can show a unique name. By default returns Name().
 * 
 * Avoid to have exceptions in the thread because the thread will crash. It isn't much of a problem in
 * recurring since it is caught but in the others, that might lead to unexpected results.
 * 
 * In order to start it:
 * myThread * mt = new myThread(PARAMETERS);
 * myThread->NextThread(NEXT_THREAD);
 * myThread->init(); // Optionally set sleep time in ns
 * myThread->start();
 * 
 * To stop it:
 * myThread->stop(); // Or ThreadFinished() can be called from within recurring to indicate 
 *                   //  the thread is done. It will allow to free some resources.
 *                   // Set the parameter to true (default false) if you wan the thread to wait
 *                   // for the queue to be empty before finishing.
 * Other useful functions:
 * myThread()->Name() : Display the name of the thread
 * myThread()->Status(): Get the status of the thread.
 */

namespace wifibeat {

	enum threadStatus {
				Created,
				Initializing,
				Initialized,
				InitializationFailed,
				Starting,
				StartingFailed,
				Started,
				Running,
				Stopping,
				Stopped,
				Crashed,
				Aborted,
				Killed
	};

	template <class T> class ThreadWithQueue {
		protected:
			queue <T *> getAllItemsFromInputQueue();

			bool sendToNextThreadsQueue(T * item);
			bool addItemToInputQueue(T * item);

			virtual bool init_function();
			virtual void recurring() = 0; // Short loop that is run
			virtual bool allQueuesEmpty();
			void Name(const string & name);

			// To be called in the loop 
			void ThreadFinished();

		private:
			vector<ThreadWithQueue *> _nextThreads;

			pthread_mutex_t _threadMutex;
			bool _threadMutexInit;
			string _name;
			thread * _thread;

			void Status(threadStatus newStatus);
			pthread_mutex_t _statusMutex;
			bool _statusMutexInit;
			volatile threadStatus _status;

			// Wait for empty queue when stopping?
			bool _stopWaitQueueIsEmpty;

			// XXX: Maybe replace it with ConcurrentQueue
			// XXX: Will need to assess performance of both
			boost::lockfree::queue<T *, boost::lockfree::capacity<1000> > _inputQueue;
			// There is no output queue at all. The way it works it that we just
			// put the stuff to the next thread's input queue. So that means, the first threads
			// will not have anything in their queue.

			// Sleep time between the loops
			std::chrono::nanoseconds * _loopSleepTimeNS;

			// When starting the thread, this function is pretty much a wrapper that will call
			// the virtual function recurring() that is implemented by the thread.
			// It also takes care of doing checks, ending thread, sleeping between loops, etc.
			void _loop();

		public:
			ThreadWithQueue();
			virtual ~ThreadWithQueue();
			virtual string toString();
			bool AddNextThread(ThreadWithQueue * nextThread);
			threadStatus Status();
			bool init(const unsigned long long int ns = 1000000); // 1ms by default

			bool start(); // Starts in the background
			bool stop(bool waitQueueIsEmpty = false); // Stops in the background
			bool kill(unsigned int ms);

			std::string Name();
	};
}

#endif // THREADWITHQUEUE_H
