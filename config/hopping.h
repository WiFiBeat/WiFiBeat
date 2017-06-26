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
#ifndef CONFIG_HOPPING_STRUCTS_H
#define CONFIG_HOPPING_STRUCTS_H

enum HTMode {
	NO_HT,
	HT20,
	HT40_PLUS,
	HT40_MINUS
};

struct channelSetting {
	unsigned int time; // in milliseconds
	unsigned int channel; // Can also be frequency
	HTMode htMode;
	channelSetting() : time(700), channel(0), htMode(NO_HT) { }
};

#endif // CONFIG_HOPPING_STRUCTS_H