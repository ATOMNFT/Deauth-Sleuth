# Deauth Sleuth v1.21 — Home Assistant / USB Serial

This guide covers the experimental USB Serial integration on the `feature/v1.21-home-assistant-serial` branch.

## Overview

Deauth Sleuth continues to run its touchscreen UI, deauth/disassociation detection, Evil Twin monitoring, RGB alerts, and optional SD logging. In parallel, it can output structured security events over USB Serial for Home Assistant, Node-RED, or another local collector.

The serial stream is newline-delimited JSON (JSONL/NDJSON): **one complete JSON object per line**.

With `HEADLESS_MODE 1`, the TFT, touch UI, RGB LED, splash screen, and CYD SD-card hardware are skipped. Monitoring and USB Serial output still start automatically.

Default baud rate:

```text
115200
```

## Configuration

Edit `Deauth-Sleuth/config.h`.

Key settings:

```cpp
static const bool SERIAL_OUTPUT_ENABLED = true;
static const unsigned long SERIAL_BAUD_RATE = 115200;
static const uint8_t SERIAL_PROTOCOL_VERSION = 1;
static const unsigned long SERIAL_HEARTBEAT_INTERVAL_MS = 30000;

static const bool SERIAL_DEAUTH_EVENTS_ENABLED = true;
static const bool SERIAL_EVIL_TWIN_EVENTS_ENABLED = true;
static const bool SERIAL_STATUS_EVENTS_ENABLED = true;

static const bool SERIAL_INCLUDE_UNWATCHED_EVENTS = true;
static const bool AUTO_START_MONITORING = true;
```

For a display-free generic ESP32 build, also set:

```cpp
#define HEADLESS_MODE 1
#define HEADLESS_SD_ENABLED 0
```

## Watched networks

Watched SSIDs and BSSIDs allow downstream automations to distinguish activity involving your own network from unrelated Wi-Fi activity nearby.

Example:

```cpp
static const char* const WATCHED_SSIDS[] = {
  "HomeWiFi",
  "IoT",
  "",
  ""
};
static const uint8_t WATCHED_SSID_COUNT = 2;

static const char* const WATCHED_BSSIDS[] = {
  "AA:BB:CC:11:22:33",
  "",
  "",
  ""
};
static const uint8_t WATCHED_BSSID_COUNT = 1;
```

Each security event contains `watched_network: true` or `watched_network: false`.

Set `SERIAL_INCLUDE_UNWATCHED_EVENTS = false` to output only security events that match a watched SSID/BSSID. Boot and status messages are still emitted.

## Event types

### boot

Sent once after startup.

```json
{"protocol":1,"event":"boot","device":"deauth_sleuth","firmware":"1.21","auto_start":true,"headless":true,"baud":115200,"sensitivity":"balanced"}
```

### status

Sent on boot and periodically according to `SERIAL_HEARTBEAT_INTERVAL_MS`.

```json
{"protocol":1,"event":"status","millis":30000,"monitoring":true,"headless":true,"scan_mode":"auto","channel":6,"packets":18420,"deauth_total":14,"evil_twin_state":"Clear","evil_twin_risk":0,"sd_ready":true,"sd_logging":false,"sensitivity":"balanced","free_heap":142000,"dropped_event_queue":0,"dropped_ap_queue":0}
```

### deauth / disassoc

```json
{"protocol":1,"event":"deauth","millis":12450,"channel":6,"rssi":-43,"reason_code":7,"source":"AA:BB:CC:11:22:33","destination":"FF:FF:FF:FF:FF:FF","bssid":"AA:BB:CC:11:22:33","ssid":"HomeWiFi","watched_network":true}
```

### evil_twin

```json
{"protocol":1,"event":"evil_twin","millis":45600,"ssid":"HomeWiFi","risk_score":6,"level":"high","reasons":"different_oui|different_channel|rssi_difference","known_bssid":"AA:BB:CC:11:22:33","suspect_bssid":"DE:AD:BE:EF:00:01","known_channel":6,"suspect_channel":11,"known_rssi":-61,"suspect_rssi":-33,"known_security":"WPA2","suspect_security":"OPEN","watched_network":true}
```

## Node-RED flow concept

A simple Node-RED pipeline can be:

```text
Serial In → Split (newline) → JSON → Switch on msg.payload.event → Home Assistant entities / notifications
```

Recommended switch outputs:

- `deauth`
- `disassoc`
- `evil_twin`
- `status`

A second switch on `msg.payload.watched_network` can separate protected-network alerts from general neighborhood activity.

## Suggested Home Assistant entities

```text
binary_sensor.deauth_sleuth_online
binary_sensor.deauth_sleuth_security_alert
binary_sensor.deauth_sleuth_evil_twin
sensor.deauth_sleuth_last_event
sensor.deauth_sleuth_last_channel
sensor.deauth_sleuth_last_rssi
sensor.deauth_sleuth_deauth_total
sensor.deauth_sleuth_evil_twin_risk
sensor.deauth_sleuth_free_heap
```

## Important behavior

- Deauth/disassoc and Evil Twin detection operate in parallel.
- `HEADLESS_MODE 1` removes the need for an attached display during operation.
- The default CYD touchscreen build remains unchanged with `HEADLESS_MODE 0`.
- Headless SD support is off by default to avoid assuming generic ESP32 SD wiring.
- USB Serial output does **not** require SD logging to be enabled.
- SD CSV logging remains available separately.
- The Wi-Fi promiscuous callback does not print JSON directly; events are queued and formatted in the normal loop to keep packet capture lightweight.
- The serial protocol is currently version `1`.

## Development status

This is a v1.21 development feature. Test the branch on hardware before merging into `main`.
