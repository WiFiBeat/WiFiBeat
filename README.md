# Description

Parses 802.11 frames from multiple sources (live or PCAP files) and store them, parsed, into Elasticsearch.

Visualize them with Kibana.

Search using Wireshark display filters.

Get alerted using ElastAlert or Elastic Watcher.

# Compilation

__Note__: Installation has only been tested on Ubuntu 16.04 for now.
__Note__: Most commands need to be run as root.

## Install Elasticsearch and Kibana

Refer to Elasticsearch documentation on https://www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html
and to Kibana documentation on https://www.elastic.co/guide/en/kibana/current/setup.html

Or follow the simplified installation steps below

```
apt-get install openjdk-8-jre
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" >> /etc/apt/sources.list.d/elastic.list
apt-get update
apt-get install elasticsearch curl kibana
```

__Note regarding Kibana and ElasticSearch__: They are often listening on 0.0.0.0, so make sure to configure the firewall to prevent access to those ports (or edit their configs) from the outside

## Install dependencies

### libtins

```
wget https://github.com/mfontanini/libtins/archive/v3.5.tar.gz
tar -zxf v3.5.tar.gz
cd libtins-3.5
apt-get install libpcap-dev libssl-dev build-essential libboost-all-dev
mkdir build
cd build
cmake ../ -DLIBTINS_ENABLE_CXX11=1
make
make install
ldconfig
```

__Note__: Radiotap parsing may fail on 3.5. Use their git repository instead.

### Other dependencies

- YAML-cpp
- POCO (for elasticbeat-cpp)
- RapidJSON (for elasticbeat-cpp)
- Boost
- libnl v3 (and libnl-genl)
- ~~libb64~~

Optional:
- tsan (Thread sanitizer, for debugging)
- wireshark-data (__manuf__ file): either generate it using ```make-manuf``` and put it in __/usr/share/wireshark/manuf__ or use __libwireshark-data__ package

#### Debian-based OS

__Note__: Make sure the system is up to date ```apt-get update && apt-get dist-upgrade``` then reboot before running the following command:

```
apt-get install libyaml-cpp-dev libpoco-dev rapidjson-dev libtsan0 libboost-all-dev libb64-dev libwireshark-data build-essential libnl-genl-3-dev
```

## Load and compile

### Install Codelite

```
apt-get install codelite codelite-plugins
```

### Load projects into CodeLite

#### Load project

1. Create workspace (__File__ -> __New__ -> __New workspace__) or use existing one. Take note of the directory.
2. Clone repositories in that newly created directory
   ```
   git clone https://github.com/WiFiBeat/WiFiBeat
   git clone https://github.com/WiFiBeat/elasticbeat-cpp
   git clone https://github.com/WiFiBeat/simplejson-cpp
   ```
3. Add projects to workspace:
   1. Right click on the workspace in the Workspace View on the left
   2. Click 'Add an existing project'
   3. Browse for the wifibeat.project file and click Open
   4. Repeat steps II and III for elasticbeat-cpp.project
   5. Repeat steps II and III for simplejson-cpp.project

### Compile

Select __wifibeat__ project by double clicking on it. It should be bold now. Now, right click on project and click on __Build__. Alternatively, hit the __Build__ menu on top then click __Build Project__.

## Configure

Copy configuration file (__wifibeat.yml__) in __/etc__ and update it.
It is fairly well documented.

## Limitations

- For now, a single wireless card (more than one untested).
- For now, a single elasticsearch output (more than one untested).
- Logstash output is not implemented yet.
- Persistence is not implemented yet.

# Usage

1. Start Elasticsearch: ```service elasticsearch start```
2. Start Kibana: ```service kibana start```
3. Plug a wireless card, put it in monitor mode (manually or using ```airmon-ng```).
4. Update the configuration file with adapter name (__/etc/wifibeat.yml__)
5. Run the tool with or without parameters. It is in __Debug__(default) or __Release__ directory depending on how it was compiled.
6. Open browser on http://localhost:5601/ then configure an index called __wifibeat-*__ for time-based events with @timestamp. Also make sure 'Expand index pattern when searching' is checked. If no data is present, index cannot be created.
7. Go to __Management__ -> __Saved Objects__ and import kibana visualizations, searches and dashboard (kibana.json).

## Parameters

```
WiFibeat v0.1

Options:
  -h [ --help ]                         Show this message
  -v [ --version ]                      Display version
  -c [ --config ] arg (=/etc/wifibeat.yml)
                                        Configuration file path
  -f [ --no-daemon ]                    Do not go in the background.
  -d [ --dump-config ]                  Display parsed configuration
  -p [ --pid ] arg (=/var/run/wifibeat.pid)
                                        Where to write PID file. Ignored if 
                                        no-daemon is set
  -n [ --no-pid ]                       Do not write PID to file. Automatically
                                        set when no-daemon is set.
  -a [ --pcap-prefix ] arg              Per interface export PCAP file prefix.
```

Everything is logged in syslog, ```grep wifibeat /var/log/syslog``` or ```tail -f /var/log/syslog | grep wifibeat``` will show them.
__Note__: If the no-daemon option is used, errors are displayed in the console too.

# Future

## WiFi-related

- Payload parsing (if unencrypted/decrypted)
- Different channel width (require support from wireless card)
  - 5/10MHz and other unusual ones
  - HT/VHT channel support
- Frequency (instead of channels) support
- Packet filtering at the source
- Multiple cards support
- PCAPng export/reading (including timestamp)
- More link types (AVS, Prism2, PPI)
- Automatically put cards in monitor mode
- Global filters (for pcap and interfaces)
- Support for Windows with Airpcap and NPCAP
- MAC address and OUI manufacturer resolution
- GPS

## ElasticSearch
- Templates/Mapping
- More configuration options
- SSL Support

## Other
- Unit testing
- More outputs (Logstash, Kafka, Redis, file, console)
- Packages (Ubuntu and others)
- Doxygen documentation
- CLI interface
- Use log4cplus for logging
- ElastAlert alerts
- Code cleanup
- Performance improvements
- Reduce dependencies
- Makefile

# Known bugs

- Packet captures are not fully ingested in Elasticsearch (not all packets are in Elasticsearch).
- Arrays are not supported in Elasticsearch. Reasons are explained in various bug reports: elastic/kibana#3333, elastic/kibana#998 and elastic/kibana#1587. If querying arrays is needed, you may look into https://github.com/istresearch/kibana-object-format (untested yet).
