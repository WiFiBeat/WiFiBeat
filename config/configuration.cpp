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
#include "configuration.h"
#include "utils/file.h"
#include "utils/stringHelper.h"
#include "utils/logger.h"
#include <string.h>
#include <cstdlib> // NULL
#include <exception>
#include <regex>
#include <string> // stoi

using std::stringstream;
using std::endl;
using std::stoi;

wifibeat::configuration* wifibeat::configuration::ms_instance = NULL;

wifibeat::configuration::configuration(const string & path) : _path(path)
{
	// Check path
	if (path.empty()) {
		throw string("Beat configuration file path cannot be empty");
	}

	// Check file exists
	if (wifibeat::utils::file::exists(path) == false) {
		throw string("File <" + path + "> does not exists");
	}

	// Parse it
	YAML::Node config;
	try {
		LOG_DEBUG("Loading configuration file");
		config = YAML::LoadFile(path);
	} catch (YAML::ParserException& e) {
		throw string("Failed parsing YAML configuration file");
	}

	try {
		LOG_DEBUG("Parsing configuration file");
		if (this->parse(config) == false) {
			throw string("Failed parsing config parameters");
		}
	} catch (YAML::ParserException& e) {
		throw string("Failed parsing YAML. Report this and include your configuration file!");
	}
}

wifibeat::configuration::~configuration()
{
}

void wifibeat::configuration::parse_wifibeat_files(const YAML::Node & node)
{
	LOG_DEBUG("Parsing wifibeat.files node");
	if (node.IsScalar() == false) {
		throw string("wifibeat.files was supposed to be a string.");
	}
	for (const string & item: wifibeat::utils::stringHelper::split(node.as<string>(), ' ')) {
		// Ignore the ones starting with #
		if (item.size() == 0 || item[0] == '#') {
			continue;
		}
		this->filesToRead.push_back(item);
	}
}

void wifibeat::configuration::parse_queues_persistent(const YAML::Node & node)
{
	LOG_DEBUG("Parsing queues.persistent node");
	if (node.IsMap() == false) {
		throw string("queues.persistent was supposed to be a map.");
	}
	this->persistentQueue.directory = PERSISTENT_QUEUE_DEFAULT_PATH;
	this->persistentQueue.maxSize = PERSISTENT_QUEUE_DEFAULT_MAX_SIZE;
	
	for (YAML::const_iterator param = node.begin(); param != node.end(); ++param) {
		string key = param->first.as<string>();
		if (key == "enabled") {
			if (param->second.IsScalar() == false) {
				throw string("queues.persistent.enabled value is invalid. Must be true or false.");
			}
			if (param->second.as<string>() == "true") {
				if (!this->persistentQueue.enabled) {
					this->persistentQueue.enabled = true;
				}
			} else if (param->second.as<string>() != "false") {
				throw string("queues.persistent.enabled value is invalid. Must be true or false.");
			}
		} else if (key == "max_size") {
			int max_size = 0;
			try {
				max_size = stoi(param->second.as<string>());
			} catch (const std::invalid_argument& ia) {
				throw string("queues.persistent.max_size value is invalid. Must be a number above 0.");
			}
			if (max_size == 0) {
				this->persistentQueue.enabled = false;
			} else if (max_size < 0) {
				throw string("queues.persistent.max_size value is invalid. Must be a number above 0.");
			} else {
				this->persistentQueue.maxSize = (unsigned int)max_size;
			}
		} else if (key == "directory") {
			if (param->second.IsScalar() == false) {
				throw string("queues.persistent.directory value is not a string.");
			}
			this->persistentQueue.directory = param->second.as<string>();
		}
	}
}

void wifibeat::configuration::parse_output_elasticsearch(const YAML::Node & node)
{
	LOG_DEBUG("Parsing output.elasticsearch node");
	if (node.IsMap() == false) {
		throw string("output.elasticsearch was supposed to be a map.");
	}
	ElasticSearchConnection conn;
	for (YAML::const_iterator param = node.begin(); param != node.end(); ++param) {
		string key = param->first.as<string>();
		if (param->second.IsNull()) {
			continue;
		}
		
		if (key == "protocol") {
			string proto = param->second.as<string>();
			if (proto.empty()) {
				continue;
			}
			wifibeat::utils::stringHelper::to_lower(proto);
			if (proto == "http") {
				conn.protocol = ESProtocol::HTTP;
			} else if (proto == "https") {
				conn.protocol = ESProtocol::HTTPS;
				throw string("HTTPS isn't supported for connecting to ElasticSearch yet.");
			} else {
				throw string("Unknown Elastic protocol: " + proto);
			}
		} else if (key == "hosts") {
			string host;
			if (param->second.IsSequence() == false) {
				throw string("Invalid ElasticSearch host value, it was supposed to be a sequence");
			}
			for (unsigned int i = 0; i < param->second.size(); ++i) {
				host = param->second[i].as<string>();
				vector<string> split = wifibeat::utils::stringHelper::split(host, ':');
				if (split.size() != 2) {
					throw string("Invalid ElasticSearch host value: " + host);
				}
				int port = 0;
				try {
					port = stoi(split[1]);
				} catch (const std::invalid_argument& ia) {
					throw string("Invalid ElasticSearch host value, port must be a number between 1 and 65535): " + host);
				}
				if (port < 1 || port > 65535) {
					throw string("Invalid ElasticSearch host value, port must be between 1 and 65535): " + host);
				}
				IPPort ipp(host = split[0], (unsigned short int)port);
				conn.hosts.push_back(ipp);
			}
		} else if (key == "password") {
			conn.password = param->second.as<string>();
		} else if (key == "username") {
			conn.username = param->second.as<string>();
		} else if (key == "enabled") {
			conn.enabled = param->second.as<string>() == "true";
			if (param->second.IsScalar() == false) {
				throw string("output.elasticsearch.enabled value is invalid. Must be true or false.");
			}
			if (param->second.as<string>() == "false") {
				conn.enabled = false;
			} else if (param->second.as<string>() != "true") {
				throw string("output.elasticsearch.enabled value is invalid. Must be true or false.");
			}
		}
		// Only some of the fields are parsed now.
	}
	// Disable it if no host are present or if disabled
	if (conn.hosts.size() != 0 && conn.enabled) {
		this->ESOutputs.push_back(conn);
	}
}

#define HOP_TU_STR_LEN 2
#define S_(x) #x
#define STR(x) S_(x)
void wifibeat::configuration::parse_wifibeat_interfaces_devices(const YAML::Node & node)
{
	LOG_DEBUG("Parsing wifibeat.interfaces.devices node");
	if (node.IsMap() == false) {
		throw string("wifibeat.interfaces.devices was supposed to be a map.");
	}
	
	for (YAML::const_iterator param = node.begin(); param != node.end(); ++param) {
	
		if (param->second.IsSequence() == false) {
			throw string("wifibeat.interfaces.devices item <" + param->first.as<string>() + "> was supposed to be a sequence.");
		}
		string card = param->first.as<string>();
		if (card.empty() || card[0] == '#') {
			continue;
		}
		vector<channelSetting> hoppingPattern;

		for (unsigned int i = 0; i < param->second.size(); ++i) {
			string chanStr = param->second[i].as<string>();

			channelSetting cs;
			cs.time = DEFAULT_HOP_TIME_MS;
			// Parse channel
			int chan = -1;

			// Channel + Hopping time
			vector<string> chan_hop = wifibeat::utils::stringHelper::split(chanStr, ':');
			if (chan_hop.size() == 2 && param->second.size() > 1) {

				// Parse hopping time
				unsigned int hopTime = 0;
				char * temp = new char[HOP_TU_STR_LEN + 1];
				memset(temp, 0, HOP_TU_STR_LEN + 1);
				// TODO: Move away from sscanf
				if (sscanf(chan_hop[1].c_str(), "%u%" STR(HOP_TU_STR_LEN) "s", &hopTime, temp) != 2 || hopTime == 0) {
					delete[] temp;
					throw string("Failed parsing hopping (or invalid hopping time) time for " + card + " on channel " + chanStr);
				}
				if (strcmp(temp, "ms") == 0) {
					cs.time = hopTime;
				} else if (strcmp(temp, "s") == 0) {
					cs.time = hopTime;
				} else {
					delete[] temp;
					throw string("Invalid hopping time unit for " + card + " on channel " + chanStr);
				}
				delete[] temp;
				
				// Parse channel
				try {
					chan = stoi(chan_hop[0]);
				} catch (const std::invalid_argument& ia) {
					throw string("Failed parsing hopping (or invalid hopping time) time for " + card + " on channel " + chan_hop[0]);
				}
			} else if (chan_hop.size() == 0) {	
				try {
					chan = stoi(chanStr);
				} catch (const std::invalid_argument& ia) {
					throw string("Failed parsing hopping (or invalid hopping time) time for " + card + " on channel " + chanStr);
				}
			} else {
				throw string("Failed parsing hopping (or invalid hopping time) time for " + card + " on channel " + chanStr);
			}

			if (chan < 1) {
				throw string("Invalid channel for " + card + ": " + chanStr);
			}
			cs.channel = chan;

			hoppingPattern.push_back(cs);
		}
		this->channelHopping.insert({card, hoppingPattern});
	}
}
#undef HOP_TU_STR_LEN

void wifibeat::configuration::parse_decryption_keys(const YAML::Node & node)
{
	LOG_DEBUG("Parsing decryption.keys node");
	if (node.IsMap() == false) {
		throw string("decryption.keys was supposed to be a map.");
	}
	for (YAML::const_iterator param = node.begin(); param != node.end(); ++param) {
		
		if (param->second.IsScalar() == false) {
			throw string("decryption.keys was supposed to be a string");
		}
		stringstream ss;
		ss << param->second.as<string>();
		string bssid, passphrase;
		if (!getline(ss, bssid, '/')) {
			throw string("Failed parsing decryption.keys BSSID/Key");
		}
		
		// Validate mac address
		if (std::regex_match (bssid, std::regex("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$") ) == false) {
			throw string ("decryption.keys item contains invalid MAC address: " + bssid);
		}

		if (!getline(ss, passphrase, '\n')) {
			throw string ("decryption.keys item contains invalid decryption key: " + bssid);
		}

		// TODO: Validate keys length

		// Fill decryption keys
		this->decryptionKeys.push_back({ param->first.as<string>(), bssid, passphrase });
	}
}

void wifibeat::configuration::parse_logging_level(const YAML::Node & node)
{
	LOG_DEBUG("Parsing logging.level node");
	if (node.IsScalar() == false) {
		throw string("logging.level was supposed to be a string.");
	}
	this->loggingLevel = node.as<string>();
}

void wifibeat::configuration::parse_wifibeat_interfaces_filters(const YAML::Node & node)
{
	LOG_DEBUG("Parsing wifibeat.interfaces.filters node");
	if (node.IsMap() == false) {
		throw string("wifibeat.interfaces.filters was supposed to be a map.");
	}
	for (YAML::const_iterator param = node.begin(); param != node.end(); ++param) {
		if (param->second.IsScalar() == false) {
			throw string("wifibeat.interfaces.filters item was supposed to be a string");
		}
		string key = param->first.as<string>();
		if (key.empty() || key[0] == '#') {
			continue;
		}
		this->interfaceFilters.insert({key, param->second.as<string>()});
	}
}

void wifibeat::configuration::parse_wifibeat_output_pcap(const YAML::Node & node)
{
	LOG_DEBUG("Parsing wifibeat.output.pcap node");
	if (node.IsMap() == false) {
		throw string("wifibeat.output.pcap was supposed to be a map.");
	}

	// PCAPOutput
	for (YAML::const_iterator param = node.begin(); param != node.end(); ++param) {
		string key = param->first.as<string>();
		if (param->second.IsNull()) {
			continue;
		}

		if (key == "enabled") {
			if (param->second.IsScalar() == false) {
				throw string("wifibeat.output.pcap.enabled value is invalid. Must be true or false.");
			}
			if (param->second.as<string>() == "true") {
				if (!this->PCAPOutput.enabled) {
					this->PCAPOutput.enabled = true;
				}
			} else if (param->second.as<string>() != "false") {
				throw string("wifibeat.output.pcap.enabled value is invalid. Must be true or false.");
			}
		} else if (key == "prefix") {
			if (param->second.IsScalar() == false) {
				throw string("wifibeat.output.pcap.prefix value should be a string.");
			}
			this->PCAPOutput.prefix = param->second.as<string>();
		}
	}
}

bool wifibeat::configuration::parse(const YAML::Node & config)
{
	string value;
	//vector<string> values;

	for (YAML::const_iterator it = config.begin(); it != config.end(); ++it) {
		if (it->second.IsNull()) {
			continue;
		}
		string key = it->first.as<string>();

		if (key == "wifibeat.files") {
			this->parse_wifibeat_files(it->second);
		} else if (key == "queues.persistent") {
			this->parse_queues_persistent(it->second);
		} else if (key == "output.elasticsearch") {
			this->parse_output_elasticsearch(it->second);
		} else if (key == "wifibeat.interfaces.devices") {
			this->parse_wifibeat_interfaces_devices(it->second);
		} else if (key == "decryption.keys") {
			this->parse_decryption_keys(it->second);
		} else if (key == "logging.level") {
			this->parse_logging_level(it->second);
		} else if (key == "wifibeat.interfaces.filters") {
			this->parse_wifibeat_interfaces_filters(it->second);
		} else if (key == "wifibeat.output.pcap") {
			this->parse_wifibeat_output_pcap(it->second);
		}
	}

	// TODO: Move interface filters to the cards (create a class for that)

	return true;
}

wifibeat::configuration* wifibeat::configuration::Instance(const string & path)
{
	if (ms_instance != NULL) {
		delete ms_instance;
	}
	ms_instance = new configuration(path);

	return Instance();
}

wifibeat::configuration* wifibeat::configuration::Instance()
{
	return ms_instance;
}

void wifibeat::configuration::Release()
{
	if (ms_instance) {
		delete ms_instance;
	}
	ms_instance = NULL;
}

string wifibeat::configuration::toString()
{
	stringstream ss;
	ss << "Persistent queues:" << endl;
	ss << "- Enabled: ";
	if (this->persistentQueue.enabled) {
		ss << "Yes" << endl;
	} else {
		ss << "No!" << endl;
	}
	ss << "- Max Size: " << this->persistentQueue.maxSize << endl;
	ss << "- Directory: " << this->persistentQueue.directory << endl;

	ss << "Files to read: " << this->filesToRead.size() << endl;
	for (const string & item: this->filesToRead) {
		ss << "- " << item << endl;
	}

	ss << "Logging level: <" << this->loggingLevel << ">" << endl;

	ss << "Decryption keys: " << this->decryptionKeys.size() << endl;
	for (const decryptionKey & dk : this->decryptionKeys) {
		ss << "- BSSID: " << dk.bssid << " - ESSID <" << dk.essid << "> - Key <" << dk.key << '>' << endl;
	}

	ss << "Channel hopping: " << this->channelHopping.size() << endl;
	for (const auto & kv: this->channelHopping) {
		string key = kv.first;
		bool first = true;
		ss << " - " << key << ": [";
		for (const channelSetting & cs: kv.second) {
			if (first) {
				first = false;
			} else {
				ss << ", ";
			}
			ss << cs.channel;
			if (cs.time != 0 && cs.time != DEFAULT_HOP_TIME_MS) {
				ss << ':' << cs.time << "ms";
			}
			if (cs.htMode != NO_HT) {
				ss << " (HT mode: ";
				switch (cs.htMode) {
					case NO_HT:
						// Avoid using -Wswitch
						break;
					case HT20:
						ss << "HT20)";
						break;
					case HT40_MINUS:
						ss << "HT40-)";
						break;
					case HT40_PLUS:
						ss << "HT40+)";
						break;
				}
			}
		}
		ss << ']' << endl;
	}

	ss << "Interface filters: " << this->interfaceFilters.size() << endl;
	for (const auto & kv: this->interfaceFilters) {
		ss << "- " << kv.first << ": " << kv.second << endl;
	}

	ss << "PCAP Export (";
	if (this->PCAPOutput.enabled) {
		ss << "enabled)" << endl;
	} else {
		ss << "disabled)" << endl;
	}
	if (this->PCAPOutput.prefix.empty() == false) {
		ss << "- Prefix: " << this->PCAPOutput.prefix << endl;
	}

	ss << "ElasticSearch outputs: " << this->ESOutputs.size() << endl;
	for (const ElasticSearchConnection & esc: this->ESOutputs) {
		ss << "- Hosts (" << esc.hosts.size() << "): [";
		bool first = true;
		for (const IPPort & ip2: esc.hosts) {
			if (first) {
				first = false;
			} else {
				ss << ", ";
			}
			ss << ip2.host << ':' << ip2.port;
		}
		ss << "] ";

		// User/pass
		if (esc.username.empty() == false) {
			ss << "with username <" << esc.username << "> password: <" << esc.password << "> ";
		}

		ss << '(' << ((esc.enabled) ? "En" : "Dis") << "abled)";
		ss << " - Bulk Max size: " << esc.bulkMaxSize << endl;
	}

	return ss.str();
}
