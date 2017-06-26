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
#ifndef UTILS_LOGGER_H
#define UTILS_LOGGER_H

#include <string>
#include <sstream>

using std::string;
using std::stringstream;

namespace wifibeat
{
	namespace utils
	{
		enum LogLevels {
			Debug = 0,
			Info = 1,
			Notice = 2,
			Warning = 3,
			Error = 4,
			Critical = 5,
			Alert = 6,
			Off = 7,
			Invalid = 99
		};

		class logger
		{
			static logger* ms_instance;

			public:
				static logger* Instance(const string & level = "info", bool logToConsole = false);
				static void Release();

				static LogLevels string2LogLevel(const string & logLevel);
				bool Log(LogLevels level, const string & message);

			private:
				LogLevels _logLevel;
				logger(const string & level, bool logToConsole = false);
				~logger();

		};

	}

}

#define LOG_DEBUG(message) wifibeat::utils::logger::Instance()->Log(wifibeat::utils::LogLevels::Debug, message)
#define LOG_INFO(message) wifibeat::utils::logger::Instance()->Log(wifibeat::utils::LogLevels::Info, message)
#define LOG_NOTICE(message) wifibeat::utils::logger::Instance()->Log(wifibeat::utils::LogLevels::Notice, message)
#define LOG_WARN(message) wifibeat::utils::logger::Instance()->Log(wifibeat::utils::LogLevels::Warning, message)
#define LOG_ERROR(message) wifibeat::utils::logger::Instance()->Log(wifibeat::utils::LogLevels::Error, message)
#define LOG_CRITICAL(message) wifibeat::utils::logger::Instance()->Log(wifibeat::utils::LogLevels::Critical, message)
#define LOG_ALERT(message) wifibeat::utils::logger::Instance()->Log(wifibeat::utils::LogLevels::Alert, message)

#endif // UTILS_LOGGER_H
