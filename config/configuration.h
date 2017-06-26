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
#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#define CONFIG_FILE_PATH "/etc/wifibeat.yml"
#define PERSISTENT_QUEUE_DEFAULT_PATH "/var/wifibeat"
#define PERSISTENT_QUEUE_DEFAULT_MAX_SIZE 1000

#include <string>
#include <vector>
#include <map>
#include <yaml-cpp/yaml.h>
#include "configstructs.h"

using std::string;
using std::vector;
using std::map;

#define DEFAULT_HOP_TIME_MS 700

namespace wifibeat {
	class configuration
	{
		static configuration* ms_instance;

	public:
		static configuration* Instance();
		static configuration* Instance(const string & path);
		static void Release();
		string toString();

		// Persistent queues
		struct persistentQueueStruct persistentQueue;

		// PCAP Writing
		PCAPOutputStruct PCAPOutput;

		// PCAP reading
		vector<string> filesToRead;

		// Decryption keys
		vector<decryptionKey> decryptionKeys;

		// Logging level
		string loggingLevel;

		// Channel hopping setting per card
		map <string, vector <channelSetting> > channelHopping;

		// Filters, per card
		map <string, string> interfaceFilters;

		// Outputs
		vector <ElasticSearchConnection> ESOutputs;
		vector <LogstashConnection> LSOutputs;

	private:
		
		configuration(const string & path);
		~configuration();
		bool parse(const YAML::Node & config);
		void parse_wifibeat_files(const YAML::Node & node);
		void parse_queues_persistent(const YAML::Node & node);
		void parse_output_elasticsearch(const YAML::Node & node);
		void parse_wifibeat_interfaces_devices(const YAML::Node & node);
		void parse_decryption_keys(const YAML::Node & node);
		void parse_logging_level(const YAML::Node & node);
		void parse_wifibeat_interfaces_filters(const YAML::Node & node);
		void parse_wifibeat_output_pcap(const YAML::Node & node);

		string _path;
	};
}
#endif // CONFIGURATION_H
