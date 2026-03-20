# Deauth Sleuth

![Deauth Sleuth header](Images/header-image.png)

Deauth Sleuth is a touchscreen ESP32 Wi-Fi monitoring project for the **ESP32-2432S028R**. It watches nearby 802.11 traffic in promiscuous mode, highlights **deauthentication / disassociation activity**, and shows live status on the built-in TFT with custom graphics and touch controls.

## What it does

- Scans Wi-Fi traffic in **Auto Scan** or **Manual Scan**
- Detects **deauth** and **disassoc** management frames
- Shows live packet activity, channel, counters, and alert visuals
- Supports **touch control** for scan mode, channel, hop speed, and SD logging
- Logs detected events to **CSV on SD card**
- Uses custom image headers for normal scan, alert state, packet capture, SD status, and splash boot screen
- Includes **RGB LED status feedback** for scan, alert, and SD write states

## Hardware / software

- **Board:** ESP32-2432S028R
- **Framework:** Arduino
- **ESP32 core:** 2.0.10
- **Display library:** TFT_eSPI
- **Touch input:** `TFT_eSPI getTouch()`

## UI controls

- **State box:** toggle **Auto Scan / Manual Scan**
- **CH area:** step channel in **Manual Scan**
- **Hop area:** cycle hop presets in **Auto Scan**
- **Bottom SD button:** toggle SD logging on or off

Touch on this setup uses a mirrored X correction:
- `tx = (SCREEN_W - 1) - rawTx;`
- Y stays normal

## SD logging

When SD logging is enabled, detected deauth and disassoc events are written to a CSV file.

Current CSV fields:

- `millis`
- `channel`
- `type`
- `frame_subtype_hex`
- `rssi`
- `reason_code`
- `source_mac`
- `dest_mac`
- `bssid`

Example header:

```csv
millis,channel,type,frame_subtype_hex,rssi,reason_code,source_mac,dest_mac,bssid
```

This makes it easier to review captured events later in a spreadsheet or log viewer.

## Project images

### Header / banner
![Project header placeholder](images/header-image.png)

### UI overview
![UI overview placeholder](images/ui-overview.png)

### Alert / deauth state
![Alert state placeholder](images/alert-state.png)

### SD logging state
![SD logging placeholder](images/sd-logging.png)

## Notes

This project is built around the current working `.ino` base for this hardware and display setup. If an older `deauth_log.csv` already exists on the SD card, delete it before testing the newer expanded CSV format so a fresh header can be created.

## Replace the placeholders

The images in `images/` are simple placeholders so the repo looks clean right away. Replace them later with:

- real photos of the device
- TFT screenshots
- wiring photos
- project banner art

## Credits

Created by **ATOMNFT / Stephen**
