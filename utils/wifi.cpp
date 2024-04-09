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
#include "wifi.h"
#include "logger.h"
#include <net/if.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <unistd.h> // close()
#include <string.h>

bool wifibeat::utils::wifi::setInterfaceUp(const string & iface)
{
	if (!isInterfaceValid(iface)) {
		return false;
	}

	int sockfd;
	struct ifreq ifr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	// flawfinder: ignore
	strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
	ifr.ifr_flags |= IFF_UP;

	bool success = -1 != ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	close(sockfd);

	return success;
}

int wifibeat::utils::wifi::channel2frequency(const unsigned int chan)
{
	// See also https://en.wikipedia.org/wiki/List_of_WLAN_channels
	if (chan == 0) {
		return -1;
	}

	if (chan < 14)
		return 2407 + chan * 5;

	if (chan == 14)
		return 2484;

	if (chan >= 183) {
		return 4000 + (chan * 5);
	}

	/* FIXME: dot11ChannelStartingFactor (802.11-2007 17.3.8.3.2) */
	return (chan + 1000) * 5;
}

bool wifibeat::utils::wifi::isInterfaceValid(const string & iface)
{

	if (iface.empty()) {
		return false;
	}

	return 0 != if_nametoindex(iface.c_str());
}

vector <string> wifibeat::utils::wifi::interfaces()
{
	vector<string> ret;
	pcap_if_t *alldevs;
	// flawfinder: ignore
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		LOG_CRITICAL("Failed obtaining interfaces list");
		throw string("Failed obtaining interfaces list");
	}

	// Loop all devices
	for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
		// add device to dev list
		if (strcmp(dev->name, "lo") != 0) {
			ret.push_back(string(dev->name));
		}
	}

	pcap_freealldevs(alldevs);

	// Need to limit even more, to just wifi interfaces
	// --- See iw code, interfaces.c -> iw dev

	return ret;
}