#Meshviewer Installation

#Software used
OS: Debian 9 (stretch)
influxdb: 1.6.1
Grafana: 5.2.2
meshviewer: https://github.com/ffrgb/meshviewer 
yanic: https://github.com/FreifunkBremen/yanic
mesh-announce: https://github.com/ffnord/mesh-announce
nginx: 1.10.3

#Installation

##mesh-announce
It is installed on a supernode. Announces the information of the gateway using respondd. 

git clone https://github.com/ffnord/mesh-announce /opt/mesh-announce
cd /opt/mesh-announce
cp /opt/mesh-announce/respondd.service /etc/systemd/system/
vi /etc/systemd/system/respondd.service

```console
[Unit]
Description=Respondd
After=network.target

[Service]
ExecStart=/opt/mesh-announce/respondd.py -d /opt/mesh-announce/providers -i br0 -i tunneldigger -b bat0 -m 10.215.0.3
Restart=always
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
```

systemctl start respondd
systemctl enable respondd
systemctl daemon-reload

## yanic
Yanic is installed on a Supernode. It collects the data of all nodes and creates the nodes.json and meshviewer.json.

https://freifunkbremen.gitbooks.io/yanic/content/docs/docs_install.html

vi /etc/yanic.conf

```console
[respondd]
enable           = true
synchronize      = "1m"
collect_interval = "1m"

[respondd.sites.ffld]
domains            = ["ffld"]

[[respondd.interfaces]]
ifname = "br0"

[webserver]
enable  = true 
bind    = "172.31.1.100:8080"
webroot = "/var/www/html/meshviewer"

[nodes]
state_path    = "/var/lib/yanic/state.json"
prune_after   = "7d"
save_interval = "5s"
offline_after = "10m"

[[nodes.output.meshviewer-ffrgb]]
enable   = true
path = "/var/www/html/meshviewer/data/meshviewer.json"

[nodes.output.meshviewer-ffrgb.filter]
no_owner = true

[[nodes.output.meshviewer]]
enable =true 
version    = 2
nodes_path = "/var/www/html/meshviewer/data/nodes.json"
graph_path = "/var/www/html/meshviewer/data/graph.json"

[nodes.output.meshviewer.filter]
no_owner = true

[[nodes.output.nodelist]]
enable   = true
path = "/var/www/html/meshviewer/data/nodelist.json"

[nodes.output.nodelist.filter]
no_owner = true

[database]
delete_after    = "7d"
delete_interval = "1h"

## [[database.connection.example]]
# Each database-connection has its own config block and needs to be enabled by adding:
#enable = true

# Save collected data to InfluxDB.
# There are the following measurments:
#   node: store node specific data i.e. clients memory, airtime
#   global: store global data, i.e. count of clients and nodes
#   firmware: store the count of nodes tagged with firmware
#   model: store the count of nodes tagged with hardware model
[[database.connection.influxdb]]
enable   = true
address  = "https://map.nerdparty.holzmolz.de:8086"
database = "ffsuew"
username = "ffsuew"
password = "xxx:"

# Tagging of the data (optional)
[database.connection.influxdb.tags]
# Tags used by Yanic would override the tags from this config
# nodeid, hostname, owner, model, firmware_base, firmware_release,frequency11g and frequency11a are tags which are already used
#tagname1 = "tagvalue 1"
# some useful e.g.:
#system   = "productive"
#site     = "ffhb"

# Graphite settings
[[database.connection.graphite]]
enable   = false
address  = "localhost:2003"
# Graphite is replacing every "." in the metric name with a slash "/" and uses
# that for the file system hierarchy it generates. it is recommended to at least
# move the metrics out of the root namespace (that would be the empty prefix).
# If you only intend to run one community and only freifunk on your graphite node
# then the prefix can be set to anything (including the empty string) since you
# probably wont care much about "polluting" the namespace.
prefix   = "freifunk"

# respondd (yanic)
# forward collected respondd package to a address
# (e.g. to another respondd collector like a central yanic instance or hopglass)
[[database.connection.respondd]]
enable   = false
# type of network to create a connection
type     = "udp6"
# destination address to connect/send respondd package
address  = "stats.bremen.freifunk.net:11001"

# Logging
[[database.connection.logging]]
enable   = false
path     = "/var/log/yanic.log"
```

## influxdb
Database storing the graph information.

wget https://dl.influxdata.com/influxdb/releases/influxdb_1.6.1_amd64.deb
sudo dpkg -i influxdb_1.6.1_amd64.deb

influx
CREATE USER admin WITH PASSWORD '<password>' WITH ALL PRIVILEGES
CREATE USER ffsuew WITH PASSWORD '<password>'
CREATE DATABASE "ffsuew"
GRANT ALL ON ffsuew TO ffsuew

```console
### Welcome to the InfluxDB configuration file.

# The values in this file override the default values used by the system if
# a config option is not specified. The commented out lines are the configuration
# field and the default value used. Uncommenting a line and changing the value
# will change the value used at runtime when the process is restarted.

# Once every 24 hours InfluxDB will report usage data to usage.influxdata.com
# The data includes a random ID, os, arch, version, the number of series and other
# usage data. No data from user databases is ever transmitted.
# Change this option to true to disable reporting.
# reporting-disabled = false

# Bind address to use for the RPC service for backup and restore.
# bind-address = "127.0.0.1:8088"

###
### [meta]
###
### Controls the parameters for the Raft consensus group that stores metadata
### about the InfluxDB cluster.
###

[meta]
  # Where the metadata/raft database is stored
  dir = "/var/lib/influxdb/meta"

  # Automatically create a default retention policy when creating a database.
  # retention-autocreate = true

  # If log messages are printed for the meta service
  # logging-enabled = true

###
### [data]
###
### Controls where the actual shard data for InfluxDB lives and how it is
### flushed from the WAL. "dir" may need to be changed to a suitable place
### for your system, but the WAL settings are an advanced configuration. The
### defaults should work for most systems.
###

[data]
  # The directory where the TSM storage engine stores TSM files.
  dir = "/var/lib/influxdb/data"

  # The directory where the TSM storage engine stores WAL files.
  wal-dir = "/var/lib/influxdb/wal"

  # The amount of time that a write will wait before fsyncing.  A duration
  # greater than 0 can be used to batch up multiple fsync calls.  This is useful for slower
  # disks or when WAL write contention is seen.  A value of 0s fsyncs every write to the WAL.
  # Values in the range of 0-100ms are recommended for non-SSD disks.
  # wal-fsync-delay = "0s"


  # The type of shard index to use for new shards.  The default is an in-memory index that is
  # recreated at startup.  A value of "tsi1" will use a disk based index that supports higher
  # cardinality datasets.
  # index-version = "inmem"

  # Trace logging provides more verbose output around the tsm engine. Turning
  # this on can provide more useful output for debugging tsm engine issues.
  # trace-logging-enabled = false

  # Whether queries should be logged before execution. Very useful for troubleshooting, but will
  # log any sensitive data contained within a query.
  # query-log-enabled = true

  # Settings for the TSM engine

  # CacheMaxMemorySize is the maximum size a shard's cache can
  # reach before it starts rejecting writes.
  # Valid size suffixes are k, m, or g (case insensitive, 1024 = 1k).
  # Values without a size suffix are in bytes.
  # cache-max-memory-size = "1g"

  # CacheSnapshotMemorySize is the size at which the engine will
  # snapshot the cache and write it to a TSM file, freeing up memory
  # Valid size suffixes are k, m, or g (case insensitive, 1024 = 1k).
  # Values without a size suffix are in bytes.
  # cache-snapshot-memory-size = "25m"

  # CacheSnapshotWriteColdDuration is the length of time at
  # which the engine will snapshot the cache and write it to
  # a new TSM file if the shard hasn't received writes or deletes
  # cache-snapshot-write-cold-duration = "10m"

  # CompactFullWriteColdDuration is the duration at which the engine
  # will compact all TSM files in a shard if it hasn't received a
  # write or delete
  # compact-full-write-cold-duration = "4h"

  # The maximum number of concurrent full and level compactions that can run at one time.  A
  # value of 0 results in 50% of runtime.GOMAXPROCS(0) used at runtime.  Any number greater
  # than 0 limits compactions to that value.  This setting does not apply
  # to cache snapshotting.
  # max-concurrent-compactions = 0

  # The threshold, in bytes, when an index write-ahead log file will compact
  # into an index file. Lower sizes will cause log files to be compacted more
  # quickly and result in lower heap usage at the expense of write throughput.
  # Higher sizes will be compacted less frequently, store more series in-memory,
  # and provide higher write throughput.
  # Valid size suffixes are k, m, or g (case insensitive, 1024 = 1k).
  # Values without a size suffix are in bytes.
  # max-index-log-file-size = "1m"

  # The maximum series allowed per database before writes are dropped.  This limit can prevent
  # high cardinality issues at the database level.  This limit can be disabled by setting it to
  # 0.
  # max-series-per-database = 1000000

  # The maximum number of tag values per tag that are allowed before writes are dropped.  This limit
  # can prevent high cardinality tag values from being written to a measurement.  This limit can be
  # disabled by setting it to 0.
  # max-values-per-tag = 100000

  # If true, then the mmap advise value MADV_WILLNEED will be provided to the kernel with respect to
  # TSM files. This setting has been found to be problematic on some kernels, and defaults to off.
  # It might help users who have slow disks in some cases.
  # tsm-use-madv-willneed = false

###
### [coordinator]
###
### Controls the clustering service configuration.
###

[coordinator]
  # The default time a write request will wait until a "timeout" error is returned to the caller.
  # write-timeout = "10s"

  # The maximum number of concurrent queries allowed to be executing at one time.  If a query is
  # executed and exceeds this limit, an error is returned to the caller.  This limit can be disabled
  # by setting it to 0.
  # max-concurrent-queries = 0

  # The maximum time a query will is allowed to execute before being killed by the system.  This limit
  # can help prevent run away queries.  Setting the value to 0 disables the limit.
  # query-timeout = "0s"

  # The time threshold when a query will be logged as a slow query.  This limit can be set to help
  # discover slow or resource intensive queries.  Setting the value to 0 disables the slow query logging.
  # log-queries-after = "0s"

  # The maximum number of points a SELECT can process.  A value of 0 will make
  # the maximum point count unlimited.  This will only be checked every second so queries will not
  # be aborted immediately when hitting the limit.
  # max-select-point = 0

  # The maximum number of series a SELECT can run.  A value of 0 will make the maximum series
  # count unlimited.
  # max-select-series = 0

  # The maxium number of group by time bucket a SELECT can create.  A value of zero will max the maximum
  # number of buckets unlimited.
  # max-select-buckets = 0

###
### [retention]
###
### Controls the enforcement of retention policies for evicting old data.
###

[retention]
  # Determines whether retention policy enforcement enabled.
  # enabled = true

  # The interval of time when retention policy enforcement checks run.
  # check-interval = "30m"

###
### [shard-precreation]
###
### Controls the precreation of shards, so they are available before data arrives.
### Only shards that, after creation, will have both a start- and end-time in the
### future, will ever be created. Shards are never precreated that would be wholly
### or partially in the past.

[shard-precreation]
  # Determines whether shard pre-creation service is enabled.
  # enabled = true

  # The interval of time when the check to pre-create new shards runs.
  # check-interval = "10m"

  # The default period ahead of the endtime of a shard group that its successor
  # group is created.
  # advance-period = "30m"

###
### Controls the system self-monitoring, statistics and diagnostics.
###
### The internal database for monitoring data is created automatically if
### if it does not already exist. The target retention within this database
### is called 'monitor' and is also created with a retention period of 7 days
### and a replication factor of 1, if it does not exist. In all cases the
### this retention policy is configured as the default for the database.

[monitor]
  # Whether to record statistics internally.
  # store-enabled = true

  # The destination database for recorded statistics
  # store-database = "_internal"

  # The interval at which to record statistics
  # store-interval = "10s"

###
### [http]
###
### Controls how the HTTP endpoints are configured. These are the primary
### mechanism for getting data into and out of InfluxDB.
###

[http]
  # Determines whether HTTP endpoint is enabled.
  # enabled = true

  # The bind address used by the HTTP service.
  # bind-address = ":8086"

  # Determines whether user authentication is enabled over HTTP/HTTPS.
  # auth-enabled = false

  # The default realm sent back when issuing a basic auth challenge.
  # realm = "InfluxDB"

  # Determines whether HTTP request logging is enabled.
  log-enabled = true

  # Determines whether the HTTP write request logs should be suppressed when the log is enabled.
  # suppress-write-log = false

  # When HTTP request logging is enabled, this option specifies the path where
  # log entries should be written. If unspecified, the default is to write to stderr, which
  # intermingles HTTP logs with internal InfluxDB logging.
  #
  # If influxd is unable to access the specified path, it will log an error and fall back to writing
  # the request log to stderr.
  # access-log-path = ""

  # Determines whether detailed write logging is enabled.
  # write-tracing = false

  # Determines whether the pprof endpoint is enabled.  This endpoint is used for
  # troubleshooting and monitoring.
  # pprof-enabled = true

  # Enables a pprof endpoint that binds to localhost:6060 immediately on startup.
  # This is only needed to debug startup issues.
  # debug-pprof-enabled = false

  # Determines whether HTTPS is enabled.
  https-enabled = true 

  # The SSL certificate to use when HTTPS is enabled.
  https-certificate = "/etc/influxdb/fullchain.pem"

  # Use a separate private key location.
  https-private-key = "/etc/influxdb/privkey.pem"

  # The JWT auth shared secret to validate requests using JSON web tokens.
  # shared-secret = ""

  # The default chunk size for result sets that should be chunked.
  # max-row-limit = 0

  # The maximum number of HTTP connections that may be open at once.  New connections that
  # would exceed this limit are dropped.  Setting this value to 0 disables the limit.
  # max-connection-limit = 0

  # Enable http service over unix domain socket
  # unix-socket-enabled = false

  # The path of the unix domain socket.
  # bind-socket = "/var/run/influxdb.sock"

  # The maximum size of a client request body, in bytes. Setting this value to 0 disables the limit.
  # max-body-size = 25000000

  # The maximum number of writes processed concurrently.
  # Setting this to 0 disables the limit.
  # max-concurrent-write-limit = 0

  # The maximum number of writes queued for processing.
  # Setting this to 0 disables the limit.
  # max-enqueued-write-limit = 0

  # The maximum duration for a write to wait in the queue to be processed.
  # Setting this to 0 or setting max-concurrent-write-limit to 0 disables the limit.
  # enqueued-write-timeout = 0


###
### [ifql]
###
### Configures the ifql RPC API.
###

[ifql]
  # Determines whether the RPC service is enabled.
  # enabled = true

  # Determines whether additional logging is enabled.
  # log-enabled = true

  # The bind address used by the ifql RPC service.
  # bind-address = ":8082"


###
### [logging]
###
### Controls how the logger emits logs to the output.
###

[logging]
  # Determines which log encoder to use for logs. Available options
  # are auto, logfmt, and json. auto will use a more a more user-friendly
  # output format if the output terminal is a TTY, but the format is not as
  # easily machine-readable. When the output is a non-TTY, auto will use
  # logfmt.
  # format = "auto"

  # Determines which level of logs will be emitted. The available levels
  # are error, warn, info, and debug. Logs that are equal to or above the
  # specified level will be emitted.
  # level = "info"

  # Suppresses the logo output that is printed when the program is started.
  # The logo is always suppressed if STDOUT is not a TTY.
  # suppress-logo = false

###
### [subscriber]
###
### Controls the subscriptions, which can be used to fork a copy of all data
### received by the InfluxDB host.
###

[subscriber]
  # Determines whether the subscriber service is enabled.
  # enabled = true

  # The default timeout for HTTP writes to subscribers.
  # http-timeout = "30s"

  # Allows insecure HTTPS connections to subscribers.  This is useful when testing with self-
  # signed certificates.
  # insecure-skip-verify = false

  # The path to the PEM encoded CA certs file. If the empty string, the default system certs will be used
  # ca-certs = ""

  # The number of writer goroutines processing the write channel.
  # write-concurrency = 40

  # The number of in-flight writes buffered in the write channel.
  # write-buffer-size = 1000


###
### [[graphite]]
###
### Controls one or many listeners for Graphite data.
###

[[graphite]]
  # Determines whether the graphite endpoint is enabled.
  # enabled = false
  # database = "graphite"
  # retention-policy = ""
  # bind-address = ":2003"
  # protocol = "tcp"
  # consistency-level = "one"

  # These next lines control how batching works. You should have this enabled
  # otherwise you could get dropped metrics or poor performance. Batching
  # will buffer points in memory if you have many coming in.

  # Flush if this many points get buffered
  # batch-size = 5000

  # number of batches that may be pending in memory
  # batch-pending = 10

  # Flush at least this often even if we haven't hit buffer limit
  # batch-timeout = "1s"

  # UDP Read buffer size, 0 means OS default. UDP listener will fail if set above OS max.
  # udp-read-buffer = 0

  ### This string joins multiple matching 'measurement' values providing more control over the final measurement name.
  # separator = "."

  ### Default tags that will be added to all metrics.  These can be overridden at the template level
  ### or by tags extracted from metric
  # tags = ["region=us-east", "zone=1c"]

  ### Each template line requires a template pattern.  It can have an optional
  ### filter before the template and separated by spaces.  It can also have optional extra
  ### tags following the template.  Multiple tags should be separated by commas and no spaces
  ### similar to the line protocol format.  There can be only one default template.
  # templates = [
  #   "*.app env.service.resource.measurement",
  #   # Default template
  #   "server.*",
  # ]

###
### [collectd]
###
### Controls one or many listeners for collectd data.
###

[[collectd]]
  # enabled = false
  # bind-address = ":25826"
  # database = "collectd"
  # retention-policy = ""
  #
  # The collectd service supports either scanning a directory for multiple types
  # db files, or specifying a single db file.
  # typesdb = "/usr/local/share/collectd"
  #
  # security-level = "none"
  # auth-file = "/etc/collectd/auth_file"

  # These next lines control how batching works. You should have this enabled
  # otherwise you could get dropped metrics or poor performance. Batching
  # will buffer points in memory if you have many coming in.

  # Flush if this many points get buffered
  # batch-size = 5000

  # Number of batches that may be pending in memory
  # batch-pending = 10

  # Flush at least this often even if we haven't hit buffer limit
  # batch-timeout = "10s"

  # UDP Read buffer size, 0 means OS default. UDP listener will fail if set above OS max.
  # read-buffer = 0

  # Multi-value plugins can be handled two ways.
  # "split" will parse and store the multi-value plugin data into separate measurements
  # "join" will parse and store the multi-value plugin as a single multi-value measurement.
  # "split" is the default behavior for backward compatability with previous versions of influxdb.
  # parse-multivalue-plugin = "split"
###
### [opentsdb]
###
### Controls one or many listeners for OpenTSDB data.
###

[[opentsdb]]
  # enabled = false
  # bind-address = ":4242"
  # database = "opentsdb"
  # retention-policy = ""
  # consistency-level = "one"
  # tls-enabled = false
  # certificate= "/etc/ssl/influxdb.pem"

  # Log an error for every malformed point.
  # log-point-errors = true

  # These next lines control how batching works. You should have this enabled
  # otherwise you could get dropped metrics or poor performance. Only points
  # metrics received over the telnet protocol undergo batching.

  # Flush if this many points get buffered
  # batch-size = 1000

  # Number of batches that may be pending in memory
  # batch-pending = 5

  # Flush at least this often even if we haven't hit buffer limit
  # batch-timeout = "1s"

###
### [[udp]]
###
### Controls the listeners for InfluxDB line protocol data via UDP.
###

[[udp]]
  # enabled = false
  # bind-address = ":8089"
  # database = "udp"
  # retention-policy = ""

  # InfluxDB precision for timestamps on received points ("" or "n", "u", "ms", "s", "m", "h")
  # precision = ""

  # These next lines control how batching works. You should have this enabled
  # otherwise you could get dropped metrics or poor performance. Batching
  # will buffer points in memory if you have many coming in.

  # Flush if this many points get buffered
  # batch-size = 5000

  # Number of batches that may be pending in memory
  # batch-pending = 10

  # Will flush at least this often even if we haven't hit buffer limit
  # batch-timeout = "1s"

  # UDP Read buffer size, 0 means OS default. UDP listener will fail if set above OS max.
  # read-buffer = 0

###
### [continuous_queries]
###
### Controls how continuous queries are run within InfluxDB.
###

[continuous_queries]
  # Determines whether the continuous query service is enabled.
  # enabled = true

  # Controls whether queries are logged when executed by the CQ service.
  # log-enabled = true

  # Controls whether queries are logged to the self-monitoring data store.
  # query-stats-enabled = false

  # interval for how often continuous queries will be checked if they need to run
  # run-interval = "1s"

###
### [tls]
###
### Global configuration settings for TLS in InfluxDB.
###

[tls]
  # Determines the available set of cipher suites. See https://golang.org/pkg/crypto/tls/#pkg-constants
  # for a list of available ciphers, which depends on the version of Go (use the query
  # SHOW DIAGNOSTICS to see the version of Go used to build InfluxDB). If not specified, uses
  # the default settings from Go's crypto/tls package.
  # ciphers = [
  #   "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
  #   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  # ]

  # Minimum version of the tls protocol that will be negotiated. If not specified, uses the
  # default settings from Go's crypto/tls package.
  # min-version = "tls1.2"

  # Maximum version of the tls protocol that will be negotiated. If not specified, uses the
  # default settings from Go's crypto/tls package.
  # max-version = "tls1.2"
```

systemctl start influxd.service 
systemctl enable influxd.service
systemctl daemon-reload

##meshviewer
The web application containing the map and node infos.

cd /opt
git clone https://github.com/ffrgb/meshviewer.git

vi /opt/meshviewer/config.js
 ```console
 module.exports = function () {
  return {
    // Variables are NODE_ID and NODE_NAME (only a-z0-9\- other chars are replaced with _)
    'nodeInfos': [
      {
        'name': 'Clientstatistik',
        'href': 'https://map.nerdparty.holzmolz.de/grafana/render/d-solo/8agNYItmk/nodes?orgId=1&panelId=2&var-NODE={NODE_NAME}&theme=light&width=1000&height=500&t={TIME}',
  'image': 'https://map.nerdparty.holzmolz.de/grafana/render/d-solo/8agNYItmk/nodes?orgId=1&panelId=2&var-NODE={NODE_NAME}&theme=light&width=1000&height=500&t={TIME}',
        'title': 'Knoten {NODE_ID} - weiteren Statistiken'
      },
      {
        'name': 'Trafficstatistik',
        'href': 'https://map.nerdparty.holzmolz.de/grafana/render/d-solo/8agNYItmk/nodes?panelId=4&orgId=1&var-NODE={NODE_NAME}&theme=light&width=1000&height=500&t={TIME}',
        'image': 'https://map.nerdparty.holzmolz.de/grafana/render/d-solo/8agNYItmk/nodes?panelId=4&orgId=1&var-NODE={NODE_NAME}&theme=light&width=1000&height=500&t={TIME}',
        'title': 'Knoten {NODE_ID} - weiteren Statistiken'
      },
      {
        'name': 'Load',
        'href': 'https://map.nerdparty.holzmolz.de/grafana/render/d-solo/8agNYItmk/nodes?panelId=6&orgId=1&var-NODE={NODE_NAME}&theme=light&width=1000&height=500&t={TIME}',
        'image': 'https://map.nerdparty.holzmolz.de/grafana/render/d-solo/8agNYItmk/nodes?panelId=6&orgId=1&var-NODE={NODE_NAME}&theme=light&width=1000&height=500&t={TIME}',
        'title': 'Knoten {NODE_ID} - weiteren Statistiken'
      },
      {
        'name': 'Airtime',
        'href': 'https://regensburg.freifunk.net/netz/statistik/node/{NODE_ID}/',
        'image': 'https://grafana.regensburg.freifunk.net/render/d-solo/000000026/node?panelId=5&from=now-7d&var-node={NODE_ID}&width=650&height=350&theme=light&_t={TIME}',
        'title': 'Knoten {NODE_ID} - weiteren Statistiken'
      }
    ],
    'linkInfos': [
      {
        'name': 'Statistik für alle Links zwischen diese Knoten',
        'image': 'https://grafana.regensburg.freifunk.net/render/d-solo/000000026/node?panelId=7&var-node={SOURCE_ID}&var-nodetolink={TARGET_ID}&from=now-7d&&width=650&height=350&theme=light&_t={TIME}',
        'title': 'Linkstatistik des letzten Tages, min und max aller Links zwischen diesen Knoten'
      }
    ],
    // Array of data provider are supported
    'dataPath': [
      'https://map.nerdparty.holzmolz.de/data/'
    ],
    'siteName': 'Freifunk Suedpfalz',
    'mapLayers': [
      {
        'name': 'OpenStreetMap.HOT',
        'url': 'https://{s}.tile.openstreetmap.fr/hot/{z}/{x}/{y}.png',
        'config': {
          'maxZoom': 19,
          'attribution': '&copy; Openstreetmap France | &copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        }
      },
      {
        'name': 'HERE',
        // Please use your own API key - Free plan is on right side after the pay plans
        'url': 'https://{s}.base.maps.api.here.com/maptile/2.1/maptile/newest/normal.day/{z}/{x}/{y}/256/png8?app_id=YOUR_KEY&app_code=YOUR_CODE&lg=deu',
        'config': {
          'attribution': 'Map &copy; 1987-2014 <a href="http://developer.here.com">HERE</a>',
          'subdomains': '1234',
          'maxZoom': 20
        }
      },
      {
        'name': 'Esri.WorldImagery',
        'url': '//server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
        'config': {
          'maxZoom': 20,
          'attribution': 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community'
        }
      },
      {
        'name': 'HERE.hybridDay',
        // Please use your own API key - Free plan is on right side after the pay plans
        'url': 'https://{s}.aerial.maps.api.here.com/maptile/2.1/maptile/newest/{variant}/{z}/{x}/{y}/256/png8?app_id=YOUR_KEY&app_code=YOUR_CODE&lg=deu',
        'config': {
          'attribution': 'Map &copy; 1987-2014 <a href="http://developer.here.com">HERE</a>',
          'subdomains': '1234',
          'variant': 'hybrid.day',
          'maxZoom': 20
        }
      }
    ],
    // Set a visible frame
    'fixedCenter': [
      // Northwest
      [
        49.3650,
        7.6660
      ],
      // Southeast
      [
        48.9692,
        8.5655 
      ] 
    ],
    'siteNames': [
      {
        'site': 'ffld',
        'name': 'Suedpfalz'
      }
    ],
    'linkList': [
      {
        'title': 'Impressum',
        'href': '/verein/impressum/'
      },
      {
        'title': 'Datenschutz',
        'href': '/verein/datenschutz/'
      }
    ]
  };
};
```
gulp

vi /opt/data/getData.sh
```console
/usr/bin/wget -r -nH --cut-dirs=2 -P /opt/meshviewer/build/data/ http://78.46.193.78:8080/data/
```
chmod +x /opt/data/getData.sh
crontab -e

```console
* * * * * /opt/data/getData.sh
```

##nginx

vi /etc/nginx/sites-enabled/default
```console
server {
        server_name  map.nerdparty.holzmolz.de;
        
        root /opt/meshviewer/build;

        autoindex off;
        charset utf-8;

        #location ~* \.(js|css|svg|png|woff|woff2|ttf|eot|json) {
        #        expires -1;
        #}

  location /grafana/ {
            proxy_pass http://127.0.0.1:3000/;
        }
  
    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/map.nerdparty.holzmolz.de/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/map.nerdparty.holzmolz.de/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

}

server {
    if ($host = map.nerdparty.holzmolz.de) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


        listen       80 ;
  listen       [::]:80 ;
        server_name  map.nerdparty.holzmolz.de;
    return 404; # managed by Certbot
}
```

systemctl start nginx
systemctl enable nginx
systemctl daemon-reload
