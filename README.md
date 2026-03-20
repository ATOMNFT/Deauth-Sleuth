# Deauth Sleuth v1

![Deauth Sleuth header](Images/header-image.png)

Deauth Sleuth is a touchscreen ESP32 Wi-Fi monitoring project for the **ESP32-2432S028R**. It watches nearby 802.11 traffic in promiscuous mode, highlights **deauthentication / disassociation activity**, and shows live status on the built-in TFT with custom graphics and touch controls. <br>
Flashing instructions below.

# UI Overview
![UI overview](images/ui-overview.png)


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

## Flashing in Arduino IDE

To flash this project in Arduino IDE, open the sketch and select **LOLIN D32** as the board.
Although the hardware target is the **ESP32-2432S028R (Cheap Yellow Display / CYD)**, this board option is used for compiling and uploading in Arduino IDE.

This project also relies on **TFT_eSPI**, so your display configuration must match the CYD hardware. A compatible **User_Setup** file has been included in the repo if needed.

Once the board and port are selected, compile and upload normally.