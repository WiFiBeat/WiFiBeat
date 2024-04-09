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
#include <stdio.h>
#include <string>
#include <cstdint>
#include <tins/tins.h>
#include <elasticbeat-cpp/elastic.h>
#include <boost/program_options.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include "config/configuration.h"
#include "threadManager.h"
#include "main.h"
#include "utils/wifi.h"
#include "utils/logger.h"
#include "utils/file.h"

using Tins::Sniffer;
using std::string;
using std::cout;
using std::endl;
using wifibeat::configuration;

namespace po = boost::program_options;

wifibeat::threadManager * _threadManager;
volatile sig_atomic_t _stop;
bool _deletePID;
app_settings _appSettings;

void signal_callback(int signum) {
        signal(signum, signal_callback);
        if (signum == SIGTERM || signum == SIGINT) {
                _stop = 1;
        }
}

bool parseArguments(const po::variables_map & vm)
{
	if (vm.count("config") && !vm["config"].as<string>().empty()) {
		_appSettings.configFilename = vm["config"].as<string>();
		try {
			configuration::Instance(_appSettings.configFilename);
		} catch (const string & e) {
			stringstream ss;
			ss << "Failed initializing configuration file: " << e;
			LOG_CRITICAL(ss.str());
			return false;
		}
	} else {
		LOG_ERROR("Missing configuration or empty path");
		return false;
	}

	if (vm.count("no-daemon")) {
		_appSettings.daemonize = false;
	}

	if (vm.count("version")) {
		_appSettings.showVersion = true;
	}
	
	if (vm.count("dump-config")) {
		_appSettings.dumpConfig = true;
	}
	
	if (vm.count("no-pid")) {
		_appSettings.noPID = true;
	}
	
	if (vm.count("pcap-prefix")) {
		_appSettings.PCAPPrefix = vm["pcap-prefix"].as<string>();
	}

	// PID file location
	_appSettings.PIDFile = vm["pid"].as<string>();

	return true;
}

void initialize()
{
	// Set default options
	_appSettings.daemonize = true;
	_appSettings.showVersion = false;
	_appSettings.noPID = false;
	_appSettings.PCAPPrefix = "";
	_stop = 0;
	_deletePID = true;
	_threadManager = NULL;

	// First, log to console.
	wifibeat::utils::logger::Instance("info", true);
}

void cleanup()
{
	configuration::Release();
	if (_deletePID && _appSettings.noPID == false && _appSettings.daemonize) {
		wifibeat::utils::file::rm(_appSettings.PIDFile);
	}
	if (_threadManager) {
		delete _threadManager;
	}
}

int main(int argc, char **argv)
{
	stringstream ss;
	bool showHelp = false;
	int ret = EXIT_SUCCESS;
	initialize();

	// Parse and verify arguments
	po::options_description desc("Options");
	desc.add_options()
		("help,h", "Show this message")
		("version,v", "Display version")
		("config,c", po::value<string>()->default_value(CONFIG_FILE_PATH), "Configuration file path")
		("no-daemon,f", "Do not go in the background.")
		("dump-config,d", "Display parsed configuration")
		("pid,p", po::value<string>()->default_value(_PID_DEFAULT_FILENAME), "Where to write PID file. Ignored if no-daemon is set")
		("no-pid,n", "Do not write PID to file. Automatically set when no-daemon is set.")
		("pcap-prefix,a", po::value<string>(), "Per interface export PCAP file prefix.");

	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);    

		if (vm.count("help")) {
			showHelp = true;
			cout << "WiFibeat v" << VERSION << endl << endl;
			cout << desc << "\n";
			return EXIT_SUCCESS;
		}
	} catch (po::error& e) {
		LOG_ERROR(e.what());
		showHelp = true;
		ret = EXIT_FAILURE;
	}

	if (!showHelp) {
		showHelp = !parseArguments(vm);
		if (showHelp) {
			ret = EXIT_FAILURE;
		}
	}

	if (showHelp) {
		cout << "WiFibeat v" << VERSION << endl;
		cout << endl << desc << endl;
		return ret;
	}

	if (_appSettings.showVersion) {
		cout << VERSION << endl;
		return EXIT_SUCCESS;
	} else {
		// Show version
		LOG_INFO("WiFibeat v" + string(VERSION));
	}

	if (_appSettings.dumpConfig) {
		ss << "Parsed configuration file <" << _appSettings.configFilename << '>' << endl;
		ss << configuration::Instance()->toString();
		LOG_INFO(ss.str());
		cleanup();
		return EXIT_SUCCESS;
	}

	// Write PID file?
	if (_appSettings.noPID == false && _appSettings.daemonize) {
		_deletePID = wifibeat::utils::file::writePID(_appSettings.PIDFile);
		if (_deletePID == false) {
			LOG_ERROR("Failed writing PID file: " + _appSettings.PIDFile);
		}
	}

	// XXX: For now LS is not supported
	if (configuration::Instance()->LSOutputs.size() != 0) {
		LOG_ERROR("Logstash outputs are not supported yet, comment them out!");
		cleanup();
		return EXIT_FAILURE;
	}

	if (configuration::Instance()->ESOutputs.size() == 0 /*&& configuration::Instance()->LSOutputs.size() == 0 */) {
		LOG_ERROR("No Elasticsearch outputs present");
		cleanup();
		return EXIT_FAILURE;
	}

	// Check for root priviliges
	if (configuration::Instance()->channelHopping.size() != 0 && geteuid() != 0) {
		LOG_ERROR("Root privilieges are required to capture on network interfaces");
		cleanup();
		return EXIT_FAILURE;
	}

	for (const auto & dk: configuration::Instance()->channelHopping) {
		if (!wifibeat::utils::wifi::isInterfaceValid(dk.first)) {
			LOG_ERROR("Interface <" + dk.first + "> mentioned in wifibeat.interfaces.devices doesn't exists, aborting.");
			cleanup();
			return EXIT_FAILURE;
		}
	}
	
	for (const auto & dk: configuration::Instance()->interfaceFilters) {
		if (!wifibeat::utils::wifi::isInterfaceValid(dk.first)) {
			ss << "Interface <" << dk.first << "> mentioned in wifibeat.interfaces.filters doesn't exists, aborting.";
			LOG_ERROR(ss.str());
			cleanup();
			return EXIT_FAILURE;
		}
	}

	// Daemonize
	if (_appSettings.daemonize) {
		if (daemon(1, 0) == -1) {
			LOG_ERROR("Failed to daemonize. Err #: " + std::to_string(errno));
			cleanup();
			return EXIT_FAILURE;
		}
		
		// Send SIGTERM to stop cleanly
		signal(SIGTERM, signal_callback);

		// Reopen logger 
		wifibeat::utils::logger::Release();
		wifibeat::utils::logger::Instance(wifibeat::configuration::Instance()->loggingLevel);
	} else {
		// Use Ctrl-C to stop
		signal(SIGINT, signal_callback);
	}

	LOG_INFO("Initializing ...");
	_threadManager = new wifibeat::threadManager(_appSettings.PCAPPrefix);
	bool success = _threadManager->init();
	configuration::Release();
	if (!success) {
		LOG_ERROR("Failed initializing thread manager, aborting.");
		cleanup();
		return EXIT_FAILURE;
	}

	LOG_INFO("Starting ...");
	if (!_threadManager->start()) {
		LOG_ERROR("Failed starting threads, aborting.");
		cleanup();
		return EXIT_FAILURE;
	}

	LOG_INFO("Started");

	// Wait
	while (!_stop && !_threadManager->canStop()) {
		sleep(1);
	}

	LOG_INFO("Stopping ...");
	_threadManager->stop();
	cleanup();

	LOG_INFO("Stopped");
	LOG_INFO("See you later, alligator");
	return ret;
}
