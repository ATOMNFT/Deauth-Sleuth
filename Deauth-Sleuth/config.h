#pragma once

/*
  ============================================================
  Deauth Sleuth - User Adjustable Settings
  Board: ESP32-2432S028R / Lolin D32 board selection
  ============================================================

  Change values in this file to tune the hardware, display,
  scanner, logging, and Evil Twin detector behavior.

  Runtime state, queues, records, enums, and program logic remain
  in Deauth-Sleuth.ino.
*/

// ============================================================
// Splash screen
// ============================================================
static const unsigned long SPLASH_TIME_MS = 2800;

// ============================================================
// RGB LED
// ============================================================
#define B_PIN 17
#define G_PIN 16
#define R_PIN 4

// Set to 1 for a common-anode/inverted RGB LED, or 0 otherwise.
#define RGB_INVERTED 1

static const unsigned long LED_ALERT_HOLD_MS = 650;
static const unsigned long LED_SD_FLASH_MS   = 140;

// ============================================================
// Sprite brightness and buffers
// ============================================================
static const float PACKET_SPRITE_BRIGHTNESS = 1.20f;
static const float SD_SPRITE_BRIGHTNESS     = 1.15f;

static const int PACKET_SPRITE_BUFFER_W = 96;
static const int PACKET_SPRITE_BUFFER_H = 96;
static const int SD_SPRITE_BUFFER_W     = 24;
static const int SD_SPRITE_BUFFER_H     = 24;

// ============================================================
// SD card and CSV files
// ============================================================
static const int SD_CS_PIN   = 5;
static const int SD_SCK_PIN  = 18;
static const int SD_MISO_PIN = 19;
static const int SD_MOSI_PIN = 23;

static const char* const LOG_FILE_PATH = "/deauth_log.csv";
static const char* const EVIL_TWIN_LOG_FILE_PATH = "/evil_twin_log.csv";

static const unsigned long SD_FLASH_DURATION_MS = 350;

// Queue sizes must be at least 2.
static const uint8_t LOG_QUEUE_SIZE = 32;
static const uint8_t EVIL_TWIN_LOG_QUEUE_SIZE = 8;

// Maximum SD records written during one loop pass.
static const uint8_t DEAUTH_SD_WRITES_PER_LOOP = 4;
static const uint8_t EVIL_TWIN_SD_WRITES_PER_LOOP = 2;

// ============================================================
// Screen and layout
// ============================================================
static const int SCREEN_W = 320;
static const int SCREEN_H = 240;
static const int HEADER_H = 24;

// Header SD icon
static const int SD_ICON_X = 200;
static const int SD_ICON_Y = 0;

// Packet artwork panel
static const int SPRITE_PANEL_X = 8;
static const int SPRITE_PANEL_Y = 32;
static const int SPRITE_PANEL_W = 112;
static const int SPRITE_PANEL_H = 112;

static const int SPRITE_X = 16;
static const int SPRITE_Y = 40;

// State / Twin status panel
static const int SPRITE_INFO_X = 8;
static const int SPRITE_INFO_Y = 150;
static const int SPRITE_INFO_W = 112;
static const int SPRITE_INFO_H = 40;

// Packet graph
static const int GRAPH_X = 128;
static const int GRAPH_Y = 32;
static const int GRAPH_W = 184;
static const int GRAPH_H = 102;

// Statistics panel
static const int STATS_X = 128;
static const int STATS_Y = 140;
static const int STATS_W = 184;
static const int STATS_H = 50;

// Bottom SD button
static const int TOUCH_SD_X = 8;
static const int TOUCH_SD_Y = 198;
static const int TOUCH_SD_W = 304;
static const int TOUCH_SD_H = 34;

// Graph plot area
static const int GRAPH_POINTS = 64;
static const int GRAPH_PLOT_X = GRAPH_X + 4;
static const int GRAPH_PLOT_Y = GRAPH_Y + 20;
static const int GRAPH_PLOT_W = GRAPH_W - 8;
static const int GRAPH_PLOT_H = GRAPH_H - 24;

// ============================================================
// Touch zones
// ============================================================
static const int TOUCH_MODE_X = SPRITE_INFO_X;
static const int TOUCH_MODE_Y = SPRITE_INFO_Y;
static const int TOUCH_MODE_W = SPRITE_INFO_W;
static const int TOUCH_MODE_H = SPRITE_INFO_H;

static const int TOUCH_CH_X = 0;
static const int TOUCH_CH_Y = 0;
static const int TOUCH_CH_W = 68;
static const int TOUCH_CH_H = HEADER_H;

static const int TOUCH_HOP_X = 52;
static const int TOUCH_HOP_Y = 0;
static const int TOUCH_HOP_W = 104;
static const int TOUCH_HOP_H = HEADER_H;

// ============================================================
// UI colors - RGB565 / TFT_eSPI colors
// ============================================================
#define COL_BG         TFT_BLACK
#define COL_PANEL      0x10A2
#define COL_PANEL2     0x18E3
#define COL_BORDER     TFT_VIOLET
#define COL_TEXT       TFT_WHITE
#define COL_DIM        0xBDF7
#define COL_ACCENT     TFT_GREEN
#define COL_ALERT      TFT_RED
#define COL_LOG        TFT_CYAN
#define COL_GRAPH_BG   0x0841
#define COL_GRID       0x2104
#define COL_BTN_ON     0x0400
#define COL_BTN_OFF    0x4000
#define COL_WARN       0xFD20


// ============================================================
// Alert sensitivity profile
// ============================================================
// Select one profile below. This controls both the deauth burst
// alert and the Evil Twin suspicious/high-risk score thresholds.
//
// SENSITIVITY_LOW:
//   Fewer alerts; best for busy Wi-Fi environments.
//
// SENSITIVITY_BALANCED:
//   Recommended default and closest to the current behavior.
//
// SENSITIVITY_HIGH:
//   Faster alerts; may produce more false positives.
#define SENSITIVITY_LOW       0
#define SENSITIVITY_BALANCED  1
#define SENSITIVITY_HIGH      2

#define ALERT_SENSITIVITY_PROFILE SENSITIVITY_BALANCED  // Change this setting if needed

#if ALERT_SENSITIVITY_PROFILE == SENSITIVITY_LOW

  // Require 5 deauth/disassoc frames inside 3 seconds.
  static const uint8_t DEAUTH_BURST_THRESHOLD = 5;
  static const unsigned long DEAUTH_BURST_WINDOW_MS = 3000;

  static const uint8_t EVIL_TWIN_SUSPICIOUS_SCORE = 4;
  static const uint8_t EVIL_TWIN_HIGH_RISK_SCORE = 7;

#elif ALERT_SENSITIVITY_PROFILE == SENSITIVITY_HIGH

  // Alert on the first deauth/disassoc frame.
  static const uint8_t DEAUTH_BURST_THRESHOLD = 1;
  static const unsigned long DEAUTH_BURST_WINDOW_MS = 1500;

  static const uint8_t EVIL_TWIN_SUSPICIOUS_SCORE = 2;
  static const uint8_t EVIL_TWIN_HIGH_RISK_SCORE = 4;

#elif ALERT_SENSITIVITY_PROFILE == SENSITIVITY_BALANCED

  // Require 3 deauth/disassoc frames inside 2 seconds.
  static const uint8_t DEAUTH_BURST_THRESHOLD = 3;
  static const unsigned long DEAUTH_BURST_WINDOW_MS = 2000;

  static const uint8_t EVIL_TWIN_SUSPICIOUS_SCORE = 3;
  static const uint8_t EVIL_TWIN_HIGH_RISK_SCORE = 5;

#else
  #error "Invalid ALERT_SENSITIVITY_PROFILE selection in config.h"
#endif

// ============================================================
// Wi-Fi scanning and channel hopping
// ============================================================
static const uint8_t MIN_CHANNEL = 1;
static const uint8_t MAX_CHANNEL = 13;
static const uint8_t DEFAULT_CHANNEL = 1;

static const unsigned long HOP_PRESETS[] = {
  100, 150, 250, 400, 500, 750, 1000, 1500, 2000
};

static const uint8_t HOP_PRESET_COUNT =
  sizeof(HOP_PRESETS) / sizeof(HOP_PRESETS[0]);

// Index 5 selects 750 ms from the list above.
static const uint8_t DEFAULT_HOP_PRESET_INDEX = 5;

// Deauth alert artwork duration.
static const unsigned long DEAUTH_VISUAL_DURATION_MS = 650;

// ============================================================
// Evil Twin detector
// ============================================================
static const uint8_t AP_OBSERVATION_QUEUE_SIZE = 24;
static const uint8_t AP_TABLE_SIZE = 32;

// Initial baseline-learning time.
static const unsigned long EVIL_TWIN_LEARNING_MS = 45000;

// Remove AP records that have not been seen for this long.
static const unsigned long AP_RECORD_TTL_MS = 180000;

// Periodic Twin: Clear heartbeat.
static const unsigned long TWIN_CLEAR_SHOW_INTERVAL_MS = 15000;
static const unsigned long TWIN_CLEAR_SHOW_TIME_MS = 2500;

// Avoid repeatedly logging the same persistent AP pair.
static const unsigned long EVIL_TWIN_RELOG_INTERVAL_MS = 60000;

// Detector comparison threshold.
static const int EVIL_TWIN_RSSI_DIFFERENCE_DB = 25;

// Risk-score weights.
static const uint8_t TWIN_SCORE_SECURITY_MISMATCH = 4;
static const uint8_t TWIN_SCORE_DIFFERENT_OUI = 2;
static const uint8_t TWIN_SCORE_DIFFERENT_CHANNEL = 1;
static const uint8_t TWIN_SCORE_RSSI_DIFFERENCE = 1;
static const uint8_t TWIN_SCORE_NEW_AFTER_LEARNING = 2;
static const uint8_t TWIN_SCORE_MULTIPLE_BSSIDS = 1;

// Processing and visual timing.
static const uint8_t AP_OBSERVATIONS_PER_LOOP = 8;
static const unsigned long EVIL_TWIN_VISUAL_DURATION_MS = 1200;

static_assert(DEAUTH_BURST_THRESHOLD >= 1,
              "DEAUTH_BURST_THRESHOLD must be at least 1");
static_assert(DEAUTH_BURST_WINDOW_MS >= 100,
              "DEAUTH_BURST_WINDOW_MS is too short");
static_assert(EVIL_TWIN_SUSPICIOUS_SCORE < EVIL_TWIN_HIGH_RISK_SCORE,
              "Evil Twin suspicious score must be below high-risk score");

static_assert(DEFAULT_HOP_PRESET_INDEX < HOP_PRESET_COUNT,
              "DEFAULT_HOP_PRESET_INDEX is outside HOP_PRESETS");
static_assert(MIN_CHANNEL <= DEFAULT_CHANNEL &&
              DEFAULT_CHANNEL <= MAX_CHANNEL,
              "DEFAULT_CHANNEL must be inside MIN_CHANNEL/MAX_CHANNEL");
static_assert(LOG_QUEUE_SIZE >= 2, "LOG_QUEUE_SIZE must be at least 2");
static_assert(EVIL_TWIN_LOG_QUEUE_SIZE >= 2,
              "EVIL_TWIN_LOG_QUEUE_SIZE must be at least 2");
static_assert(AP_OBSERVATION_QUEUE_SIZE >= 2,
              "AP_OBSERVATION_QUEUE_SIZE must be at least 2");
