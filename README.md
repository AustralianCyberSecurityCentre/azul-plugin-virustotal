# Azul Plugin Virustotal

The following components provide support for integrating virustotal metadata and samples into
AZUL processing flows. Several components rely on having a 'premium' subscription to VT
to enable access to file submission feeds and bulk downloading.

The project only supports V3 of the Virustotal api.

### Build Locally

```
go build -v -tags netgo -ldflags '-w -extldflags "-static"' -o ./bin/vt main.go
```

# Docker Builds

A dockerfile is provided for building the Azul plugin.
To use the container for a build run the following
(or similar if your ssh private and public key for accessing Azure is in a non-standard file):

Example Build:

```bash
docker build \
--build-arg ssh_prv_key="$(cat ~/.ssh/id_rsa)" \
--build-arg ssh_pub_key="$(cat ~/.ssh/id_rsa.pub)" .
```

This provides your public and private ssh keys as build arguments to the docker container.

## VirusTotal Feed Loader (vt load)

This command-line tool is used to batch load submission metadata feeds from VT private
API endpoints. It currently only support the V3 file feed API as defined at:
https://docs.virustotal.com/reference/feeds-file

The loader will transform these into binary events that Azul can process and render.
It may also create 'download' requests for vtdownload to retrieve depending on configured rules.

The loader can work in three modes:

- Direct - Direct downloading the latest file feed (tracking state) via an appropriate API key.
  Minutely bundles will be fetched and loaded while not caught up. It is
  intended to be run frequently via cron or k8s job.

- Server - Run in a server mode where jsonlines must be POSTed to the server. This is useful
  where you have json files in an external system (like nifi) and want to forward them into Azul.

### Events:

Events Produced:

- entity_type: `binary`, event: `mapped`
  - per seen sha256, generated Azul metadata
- entity_type: `download`, event: `download_requested`
  - request retrieval of sha256 bytes for interesting samples

### Usage:

```bash
# client mode - reach out to virustotal.com
VIRUSTOTAL_APIKEY=xxxx \
STATEDIR=~/.vtload \
PLUGIN_DATA_URL=http://dispatcher:8111 \
PLUGIN_EVENTS_URL=http://dispatcher:8111 \
RULES_ROOT=testdata/select_rules/example \
vt load
```

```bash
# server mode - must post data to vt load server
# apikey must be empty string
VIRUSTOTAL_APIKEY="" \
PLUGIN_DATA_URL=http://dispatcher:8111 \
PLUGIN_EVENTS_URL=http://dispatcher:8111 \
vt tload
# post virustotal metadata to server
bzcat sample.json.bz2 | curl \
-H "Content-Type: application/json" \
-X POST \
--data-binary @- \
http://localhost:8854
```

### Settings

| Name                     | Default                    | Description                                                                     |
| ------------------------ | -------------------------- | ------------------------------------------------------------------------------- |
| VIRUSTOTAL               | https://www.virustotal.com | location of virustotal api                                                      |
| VIRUSTOTAL_APIKEY        |                            | API key for virustotal, if set will run in 'client' mode                        |
| PLUGIN_DATA_URL          | http://localhost:8111      | URL to dispatcher that handles streams                                          |
| PLUGIN_EVENTS_URL        | http://localhost:8111      | URL to dispatcher that handles events                                           |
| DISPATCHER_MAX_AGE_HOURS | 72                         | records older than this will be dropped                                         |
| STATEDIR                 | .loadstate                 | in 'client' mode, temporary files will be stored here                           |
| PACKAGE_LIMIT            | -1                         | in 'client' mode, will exit after downloading this many batches from virustotal |
| RULES_ROOT               | ./select_rules             | yaml select rules loaded from this directory                                    |
| MAX_DOWNLOAD_SIZE_MB     | 20MB                       | Files over this size will never be downloaded                                   |

## VirusTotal Query (vt query)

While the vision for VT integration in AZUL 3 was bulk import all available metadata, this may not always be practical due
to resource constraints and not all historical data may be available based on when feed subscriptions started.

Instead this plugin complements the bulk metadata loading by subscribing for non-VirusTotal binary events and querying for
those binary hashes individually, using the quota'ed File Report API (https://docs.virustotal.com/reference/feeds-file).
As the format for the report matches that produced by the file feed endpoint/vtload, binary events can be created.
The end result being binaries submitted via other sources should be enriched with any available VirusTotal metadata.

## Events:

Events Consumed:

- entity_type: `binary`, event: !`binary_enriched` !`source=virustotal`

Events Produced:

- entity_type: `binary`, event: `binary_sourced`
  - if able to find via VirusTotal query

## Usage:

    VIRUSTOTAL_APIKEY=xxx PLUGIN_DATA_URL=http://dispatcher:8111 PLUGIN_EVENTS_URL=http://dispatcher:8111 azul-vtquery

## VirusTotal Downloader (vt download)

This service listens for download request events to trigger download attempts via
the VirusTotal API. These are currently downloaded via the VirusTotal V3 Private API.

Requests can contain category quotas to limit the number of downloads in a 24 hour period
and the downloader will attempt to apply these limits in a distributed fashion. Downloads
for categories that have reached their daily limit will be skipped.

Download requests can either contain a short-lived download URL (as provided by VT in their
file feed API records) or the hash to download via the VT quota limited API.

A request can also specify whether to attempt to download corresponding PCAP for samples
via the VT quota limited API.

Any successful downloads will produce an AZUL Binary event containing the content
(and PCAP if available) info for downstream processing by binary plugins.

### Events:

Events Consumed:

- entity_type: `download`, event: `download_requested`
- entity_type: `download`, event: `download_success`
  - for quota tracking

Events Produced:

- entity_type: `download`, event: `download_success`
  - binary events produced or system already has file
  - entity_type: `download`, event: `download_failed`
  - unable to download requested file
- entity_type: `binary`, event: `binary_sourced`
  - details of successful downloaded content/pcap

### Usage:

```bash
VIRUSTOTAL_APIKEY=xxxx \
PLUGIN_DATA_URL=http://dispatcher:8111 \
PLUGIN_EVENTS_URL=http://dispatcher:8111 \\
vt download
```

## VirusTotal HuntFeed (azul-vthuntfeed)

WARNING: This hasn't been tested in a long time and was written against an early V3 beta API which has probably since changed.

This command is intended to be run from a cron or cloud job service to periodically download
user results from VirusTotal Live Hunts.

These results are forwarded as binary records to AZUL, with hunt metadata mapped to the source info.
Matched file results are automatically forwarded as download requests to the VT Downloader.

### Events:

Events Produced:

- entity_type: `download`, event: `download_requested`
  - for actioning by vtdownload
- entity_type: `binary`, event: `binary_matched`
  - source metadata for the hunt match

### Usage:

```bash
VIRUSTOTAL_APIKEY=xxxx \
STATEDIR=~/.hunt \
PLUGIN_DATA_URL=http://dispatcher:8111 \
PLUGIN_EVENTS_URL=http://dispatcher:8111 \
azul-vthuntfeed
```
