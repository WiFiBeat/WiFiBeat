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
#ifndef CONFIG_OUTPUT_BASE_H
#define CONFIG_OUTPUT_BASE_H

#include <vector>
#include <string>

using std::string;
using std::vector;

struct IPPort {
	string host;
	unsigned short int port;
	explicit IPPort() : host(""), port(0) { }
	explicit IPPort(const string & Host) : host(Host), port(0) { }
	explicit IPPort(const string & Host, const unsigned short int Port) : host(Host), port(Port) { }
};

struct outputSSLSettings {
	bool enabled; // true
	string verification_mode; // full
	vector <string> supportedProtocols; // TLSv1.0, TLSv1.1, TLSv1.2
	vector <string> certificateAuthorities; // /etc/pki/root/ca.pem
	string certificate; // /etc/pki/client/cert.pem
	string key; // /etc/pki/client/cert.key
	string keyPassphrase;
	vector <string> cipherSuites;
	vector <string> curveTypes;
	outputSSLSettings() : enabled(true), verification_mode("full"), supportedProtocols({"TLSv1.0", "TLSv1.1", "TLSv1.2"}),
						certificateAuthorities({"/etc/pki/root/ca.pem"}), certificate("/etc/pki/client/cert.pem"),
						key("/etc/pki/client/cert.key") { }
};

struct outputBeatBase {
	bool enabled; // true
	vector <IPPort> hosts;
	int compressionLevel; // 0
	outputSSLSettings ssl;
	int workers; // 1
	string index;
	outputBeatBase() : enabled(true), compressionLevel(0), workers(1), index("") { }
};

#endif // CONFIG_OUTPUT_BASE_H
