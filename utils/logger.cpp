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
#include "logger.h"
#include "stringHelper.h"
#include <cstdlib> // NULL 
#include <syslog.h>

#define _LOGGER_FACILITY LOG_LOCAL5

wifibeat::utils::logger* wifibeat::utils::logger::ms_instance = NULL;

wifibeat::utils::logger::logger(const string & level, bool logToConsole)
	: _logLevel(Info)
{
	if (!level.empty()) {
		this->_logLevel = wifibeat::utils::logger::string2LogLevel(level);
		if (this->_logLevel == Invalid) {
			throw string("Invalid log level: " + level);
		}
	}

	if (logToConsole) {
		openlog(NULL, LOG_NDELAY | LOG_PERROR, _LOGGER_FACILITY);
	} else {
		openlog(NULL, LOG_NDELAY, _LOGGER_FACILITY);
	}
}

wifibeat::utils::logger::~logger()
{
	closelog();
}

wifibeat::utils::logger* wifibeat::utils::logger::Instance(const string & level, bool logToConsole)
{
	if (ms_instance == NULL) {
		ms_instance = new wifibeat::utils::logger(level, logToConsole);
	}
	return ms_instance;
}

void wifibeat::utils::logger::Release()
{
	if (ms_instance) {
		delete ms_instance;
	}
	ms_instance = NULL;
}

bool wifibeat::utils::logger::Log(LogLevels level, const string & message)
{
	if (level == Off || message.empty()) {
		return false;
	}

	// Ignore message if lower than requested
	if (level < this->_logLevel) {
		return true;
	}

	int priority = _LOGGER_FACILITY;
	switch (level) {
		case Debug:
			// debug-level message
			priority |= LOG_DEBUG;
			break;
		case Info:
			// informational message
			priority |= LOG_INFO;
			break;
		case Notice:
			// normal, but significant, condition
			priority |= LOG_NOTICE;
			break;
		case Warning:
			// warning conditions
			priority |= LOG_WARNING;
			break;
		case Error:
			// error conditions
			priority |= LOG_ERR;
			break;
		case Critical:
			// critical conditions
			priority |= LOG_CRIT;
			break;
		case Alert:
			// action must be taken immediately
			priority |= LOG_ALERT;
			break;
		default:
			// Off
			return true;
	}

	syslog(priority, "%s", message.c_str());

	return true;
}

wifibeat::utils::LogLevels wifibeat::utils::logger::string2LogLevel(const string & logLevel)
{
	if (logLevel.empty()) {
		return Off;
	}
	string level = string(logLevel);
	stringHelper::to_lower(level);

	LogLevels ret = Off;
	if (level == "debug") {
		ret = Debug;
	} else if (level == "info") {
		ret = Info;
	} else if (level == "notice") {
		ret = Notice;
	} else if (level == "warning" || level == "warn") {
		ret = Warning;
	} else if (level == "error") {
		ret = Error;
	} else if (level == "critical") {
		ret = Critical;
	} else if (level == "alert") {
		ret = Alert;
	} else {
		ret = Invalid;
	}

	return ret;
}
