/*
 *    WiFiBeat - Parse 802.11 frames and store them in ElasticSearch
 *    Copyright (C) 2017 Thomas d'Otreppe de Bouvette 
 *                       <tdotreppe@aircrack-ng.org>
 *    Thanks to dragorn (Kismet) for this helper class
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
#ifndef UTILS_LOCKER_H
#define UTILS_LOCKER_H

#include <pthread.h>
#include <time.h>

namespace wifibeat
{
	namespace utils
	{
		class Locker {
			public:
				Locker(pthread_mutex_t *in) {
					if (in == NULL) {
						lock = NULL;
						throw(std::runtime_error("mutex is NULL"));
					}
					struct timespec t;

					clock_gettime(CLOCK_REALTIME , &t);
					t.tv_sec += 3;

					if (pthread_mutex_timedlock(in, &t) != 0) {
						throw(std::runtime_error("mutex not available within 3 seconds"));
					}
					lock = in;
				}

				~Locker() {
					if (lock) {
						pthread_mutex_unlock(lock);
					}
				}
			private:
				pthread_mutex_t *lock;
		};
	}
}

#endif // UTILS_LOCKER_H
