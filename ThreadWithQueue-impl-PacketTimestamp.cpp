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
#include "ThreadWithQueue.cpp" // Including the .cpp is the important thing
#include "PacketTimestamp.h"
#include <queue>
#include <string>

using std::string;
using std::queue;
using wifibeat::ThreadWithQueue;
using wifibeat::PacketTimestamp;
using wifibeat::threadStatus;

template bool ThreadWithQueue<PacketTimestamp>::init(const unsigned long long int ns = 1000000);
template ThreadWithQueue<PacketTimestamp>::ThreadWithQueue();
template ThreadWithQueue<PacketTimestamp>::~ThreadWithQueue();
template void ThreadWithQueue<PacketTimestamp>::Name(const string & name);
template bool ThreadWithQueue<PacketTimestamp>::sendToNextThreadsQueue(PacketTimestamp * item);
template bool ThreadWithQueue<PacketTimestamp>::addItemToInputQueue(PacketTimestamp * item);
template queue <PacketTimestamp *> ThreadWithQueue<PacketTimestamp>::getAllItemsFromInputQueue();
template bool ThreadWithQueue<PacketTimestamp>::AddNextThread(ThreadWithQueue * nextThread);
template bool ThreadWithQueue<PacketTimestamp>::start();
template bool ThreadWithQueue<PacketTimestamp>::stop(bool waitQueueIsEmpty = false);
template bool ThreadWithQueue<PacketTimestamp>::kill(unsigned int ns = 0);
template threadStatus ThreadWithQueue<PacketTimestamp>::Status();
template void ThreadWithQueue<PacketTimestamp>::ThreadFinished();
template bool ThreadWithQueue<PacketTimestamp>::allQueuesEmpty();
template string ThreadWithQueue<PacketTimestamp>::toString();
