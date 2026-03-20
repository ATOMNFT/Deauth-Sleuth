/*
  ============================================================
  Deauth Sleuth v1
  Board: ESP32-2432S028R
  Framework: Arduino / ESP32 core 2.0.10
  Display: 320x240 TFT using TFT_eSPI
  Touch: TFT_eSPI getTouch()
  Created by ATOMNFT
  Deauth Sleuth is a touchscreen ESP32-based Wi-Fi monitoring
  tool built for the ESP32-2432S028R. It scans nearby wireless
  traffic, watches for deauthentication and disassociation
  activity, and presents live scanner status on the TFT using
  custom graphics, alert visuals, and touch-driven controls.

  Features include:
  - Auto Scan and Manual Scan modes
  - Touch toggle for scan state
  - Manual channel selection from the CH when in manu mode
  - Adjustable channel hop presets in Auto Scan mode
  - Splash screen and custom packet/status graphics
  - SD card status icons with on-screen logging toggle
  - CSV event logging for detected deauth/disassoc frames
  - RGB LED status feedback for scan, alerts, and SD writes

  This project is intended as a compact ESP32 wireless activity
  viewer with a simple touch interface, live feedback, and
  optional event logging for later review.
  ============================================================
*/

// ============================================================
// Libraries
// ============================================================
#include <WiFi.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <SD.h>
#include <TFT_eSPI.h>

// ============================================================
// Sprites
// ============================================================
#include "norm-packets.h"
#include "deauth-packets.h"
#include "packet-capture.h"
#include "sd-no.h"
#include "sd-off.h"
#include "sd-on.h"
#include "splash.h"

TFT_eSPI tft = TFT_eSPI();

// Forward declaration for Arduino auto-generated prototypes
struct LogEvent;


const unsigned long SPLASH_TIME_MS = 2800;

// ============================================================
// RGB LED pins / control
// ============================================================
#define B_PIN 17
#define G_PIN 16
#define R_PIN 4

// Set to 1 if your RGB LED is common-anode / inverted
#define RGB_INVERTED 1

const unsigned long LED_ALERT_HOLD_MS = 650;
const unsigned long LED_SD_FLASH_MS   = 140;

enum LedMode {
  LED_MODE_SCAN,
  LED_MODE_ALERT,
  LED_MODE_SD_FLASH
};

LedMode ledMode = LED_MODE_SCAN;
unsigned long ledModeUntilMs = 0;

static inline uint8_t ledFix(uint8_t v) {
#if RGB_INVERTED
  return 255 - v;
#else
  return v;
#endif
}

void setRgbLed(uint8_t r, uint8_t g, uint8_t b) {
  analogWrite(R_PIN, ledFix(r));
  analogWrite(G_PIN, ledFix(g));
  analogWrite(B_PIN, ledFix(b));
}

void setLedMode(LedMode mode, unsigned long holdMs = 0) {
  ledMode = mode;
  ledModeUntilMs = (holdMs > 0) ? millis() + holdMs : 0;

  switch (ledMode) {
    case LED_MODE_SCAN:
      setRgbLed(0, 255, 0);
      break;
    case LED_MODE_ALERT:
      setRgbLed(255, 0, 0);
      break;
    case LED_MODE_SD_FLASH:
      setRgbLed(0, 0, 255);
      break;
  }
}

void updateLedState() {
  if (ledModeUntilMs != 0 && millis() >= ledModeUntilMs) {
    ledModeUntilMs = 0;
    setLedMode(LED_MODE_SCAN);
  }
}



// ============================================================
// Sprite brightness controls
// ============================================================
const float PACKET_SPRITE_BRIGHTNESS = 1.20f;
const float SD_SPRITE_BRIGHTNESS     = 1.15f;

// Scratch buffers used for brightness-adjusted RGB565 drawing
uint16_t packetSpriteBuffer[96 * 96];
uint16_t sdSpriteBuffer[24 * 24];

// ============================================================
// SD card pin config
// ============================================================
static const int SD_CS_PIN   = 5;
static const int SD_SCK_PIN  = 18;
static const int SD_MISO_PIN = 19;
static const int SD_MOSI_PIN = 23;

SPIClass sdSPI(VSPI);

bool sdCardReady = false;
bool sdLoggingEnabled = false;
bool lastDrawnSdLoggingEnabled = false;
bool lastDrawnSdCardReady = false;

const char* LOG_FILE_PATH = "/deauth_log.csv";

// ============================================================
// Screen / layout
// ============================================================
static const int SCREEN_W = 320;
static const int SCREEN_H = 240;
static const int HEADER_H = 24;

// Header SD icon position
static const int SD_ICON_X = 200;
static const int SD_ICON_Y = 0;

// Dedicated sprite section
static const int SPRITE_PANEL_X = 8;
static const int SPRITE_PANEL_Y = 32;
static const int SPRITE_PANEL_W = 112;
static const int SPRITE_PANEL_H = 112;

static const int SPRITE_X = 16;
static const int SPRITE_Y = 40;

// Small panel below sprite
static const int SPRITE_INFO_X = 8;
static const int SPRITE_INFO_Y = 150;
static const int SPRITE_INFO_W = 112;
static const int SPRITE_INFO_H = 40;

// Right-side graph
static const int GRAPH_X = 128;
static const int GRAPH_Y = 32;
static const int GRAPH_W = 184;
static const int GRAPH_H = 102;

// Right-side stats
static const int STATS_X = 128;
static const int STATS_Y = 140;
static const int STATS_W = 184;
static const int STATS_H = 50;

// Bottom touch button
static const int TOUCH_SD_X = 8;
static const int TOUCH_SD_Y = 198;
static const int TOUCH_SD_W = 304;
static const int TOUCH_SD_H = 34;

// Plot area
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
// Colors
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
// Visual states
// ============================================================
enum ScannerVisualState {
  STATE_SCANNING,
  STATE_DEAUTH_SEEN,
  STATE_SD_LOGGING
};

ScannerVisualState currentState = STATE_SCANNING;
ScannerVisualState lastDrawnState = (ScannerVisualState)255;
unsigned long stateUntilMs = 0;
unsigned long sdFlashDurationMs = 350;

// ============================================================
// Scan mode / hopping
// ============================================================
enum ScanMode {
  MODE_AUTO_SCAN,
  MODE_MANUAL_SCAN
};

ScanMode scanMode = MODE_AUTO_SCAN;
ScanMode lastDrawnScanMode = (ScanMode)255;

uint8_t currentChannel = 1;
uint8_t lastDrawnChannel = 255;
const uint8_t minChannel = 1;
const uint8_t maxChannel = 13;
unsigned long lastHopMs = 0;

const unsigned long hopPresets[] = {100, 150, 250, 400, 500, 750, 1000, 1500, 2000};
const uint8_t hopPresetCount = sizeof(hopPresets) / sizeof(hopPresets[0]);
uint8_t hopPresetIndex = 5;
unsigned long hopIntervalMs = hopPresets[hopPresetIndex];
unsigned long lastDrawnHopInterval = 0xFFFFFFFF;

// ============================================================
// Packet activity
// ============================================================
volatile uint32_t totalPackets = 0;
volatile uint32_t deauthPackets = 0;
volatile uint16_t packetsThisSample = 0;
volatile uint8_t pendingDeauthEvents = 0;

uint32_t totalPacketsUi = 0;
uint32_t deauthPacketsUi = 0;
uint16_t lastActivityBurst = 0;

uint32_t lastDrawnTotalPackets = 0xFFFFFFFF;
uint32_t lastDrawnDeauthPackets = 0xFFFFFFFF;
uint16_t lastDrawnBurst = 0xFFFF;

// ============================================================
// SD event queue
// ============================================================
struct LogEvent {
  uint32_t ms;
  uint8_t channel;
  int8_t rssi;
  uint8_t subtype;
  uint8_t frameSubtypeHex;
  uint16_t reasonCode;
  uint8_t src[6];
  uint8_t dest[6];
  uint8_t bssid[6];
};

static const uint8_t LOG_QUEUE_SIZE = 32;
volatile LogEvent logQueue[LOG_QUEUE_SIZE];
volatile uint8_t logHead = 0;
volatile uint8_t logTail = 0;
volatile uint32_t droppedLogEvents = 0;

uint32_t loggedEventsCount = 0;
uint32_t lastDrawnLoggedEventsCount = 0xFFFFFFFF;
uint32_t droppedEventsUi = 0;
uint32_t lastDrawnDroppedEventsUi = 0xFFFFFFFF;

// ============================================================
// Graph
// ============================================================
uint8_t graphData[GRAPH_POINTS];
uint8_t lastDrawnGraphData[GRAPH_POINTS];
unsigned long lastGraphSampleMs = 0;
unsigned long graphSampleIntervalMs = 180;

// ============================================================
// Touch debounce
// ============================================================
bool lastTouchState = false;
unsigned long lastTouchToggleMs = 0;
unsigned long touchDebounceMs = 220;

// ============================================================
// Brightness / RGB565 helpers
// ============================================================
static inline uint8_t clamp8(int v) {
  if (v < 0) return 0;
  if (v > 255) return 255;
  return (uint8_t)v;
}

uint16_t adjustRgb565Brightness(uint16_t c, float brightness) {
  uint8_t r5 = (c >> 11) & 0x1F;
  uint8_t g6 = (c >> 5)  & 0x3F;
  uint8_t b5 = c & 0x1F;

  int r = (r5 * 255) / 31;
  int g = (g6 * 255) / 63;
  int b = (b5 * 255) / 31;

  r = clamp8((int)(r * brightness));
  g = clamp8((int)(g * brightness));
  b = clamp8((int)(b * brightness));

  uint16_t rOut = (uint16_t)((r * 31) / 255) & 0x1F;
  uint16_t gOut = (uint16_t)((g * 63) / 255) & 0x3F;
  uint16_t bOut = (uint16_t)((b * 31) / 255) & 0x1F;

  return (rOut << 11) | (gOut << 5) | bOut;
}

void prepareBrightImageBuffer(const uint16_t* src, uint16_t* dst, uint16_t count, float brightness) {
  for (uint16_t i = 0; i < count; i++) {
    dst[i] = adjustRgb565Brightness(src[i], brightness);
  }
}

void pushBrightImage(int16_t x, int16_t y, int16_t w, int16_t h, const uint16_t* src, uint16_t* scratch, float brightness) {
  prepareBrightImageBuffer(src, scratch, (uint16_t)(w * h), brightness);
  tft.setSwapBytes(true);
  tft.pushImage(x, y, w, h, scratch);
  tft.setSwapBytes(false);
}

void drawSplashScreen() {
  tft.fillScreen(TFT_BLACK);
  tft.setSwapBytes(true);
  tft.pushImage(0, 0, SPLASH_WIDTH, SPLASH_HEIGHT, splash);
  tft.setSwapBytes(false);
  delay(SPLASH_TIME_MS);
}

// ============================================================
// Helpers
// ============================================================
bool isPointInRect(int tx, int ty, int rx, int ry, int rw, int rh) {
  return (tx >= rx && tx < (rx + rw) && ty >= ry && ty < (ry + rh));
}

void pushGraphValue(uint8_t value) {
  for (int i = 0; i < GRAPH_POINTS - 1; i++) {
    graphData[i] = graphData[i + 1];
  }
  graphData[GRAPH_POINTS - 1] = value;
}

void setVisualState(ScannerVisualState newState, unsigned long durationMs = 0) {
  currentState = newState;
  stateUntilMs = (durationMs > 0) ? millis() + durationMs : 0;
}

const char* stateLabel() {
  return (scanMode == MODE_AUTO_SCAN) ? "Auto Scan" : "Manual Scan";
}

void formatMac(const uint8_t* mac, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void applyCurrentChannel() {
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

void cycleHopPreset() {
  hopPresetIndex++;
  if (hopPresetIndex >= hopPresetCount) hopPresetIndex = 0;
  hopIntervalMs = hopPresets[hopPresetIndex];
}

void stepManualChannel() {
  currentChannel++;
  if (currentChannel > maxChannel) currentChannel = minChannel;
  applyCurrentChannel();
}

bool enqueueLogEvent(uint8_t subtype, uint8_t frameSubtypeHex, uint16_t reasonCode, int8_t rssi, const uint8_t* srcMac, const uint8_t* destMac, const uint8_t* bssidMac, uint8_t ch) {
  noInterrupts();
  uint8_t nextHead = (logHead + 1) % LOG_QUEUE_SIZE;
  if (nextHead == logTail) {
    droppedLogEvents++;
    interrupts();
    return false;
  }

  logQueue[logHead].ms = millis();
  logQueue[logHead].channel = ch;
  logQueue[logHead].rssi = rssi;
  logQueue[logHead].subtype = subtype;
  logQueue[logHead].frameSubtypeHex = frameSubtypeHex;
  logQueue[logHead].reasonCode = reasonCode;
  for (int i = 0; i < 6; i++) {
    logQueue[logHead].src[i] = srcMac[i];
    logQueue[logHead].dest[i] = destMac[i];
    logQueue[logHead].bssid[i] = bssidMac[i];
  }

  logHead = nextHead;
  interrupts();
  return true;
}

bool dequeueLogEvent(LogEvent &evt) {
  bool hasItem = false;

  noInterrupts();
  if (logTail != logHead) {
    evt.ms = logQueue[logTail].ms;
    evt.channel = logQueue[logTail].channel;
    evt.rssi = logQueue[logTail].rssi;
    evt.subtype = logQueue[logTail].subtype;
    evt.frameSubtypeHex = logQueue[logTail].frameSubtypeHex;
    evt.reasonCode = logQueue[logTail].reasonCode;
    for (int i = 0; i < 6; i++) {
      evt.src[i] = logQueue[logTail].src[i];
      evt.dest[i] = logQueue[logTail].dest[i];
      evt.bssid[i] = logQueue[logTail].bssid[i];
    }

    logTail = (logTail + 1) % LOG_QUEUE_SIZE;
    hasItem = true;
  }
  interrupts();

  return hasItem;
}

// ============================================================
// SD helpers
// ============================================================
bool ensureLogFileHeader() {
  if (!sdCardReady) return false;

  if (!SD.exists(LOG_FILE_PATH)) {
    File f = SD.open(LOG_FILE_PATH, FILE_WRITE);
    if (!f) return false;
    f.println("millis,channel,type,frame_subtype_hex,rssi,reason_code,source_mac,dest_mac,bssid");
    f.close();
  }
  return true;
}

bool initSDCard() {
  sdSPI.begin(SD_SCK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);

  if (!SD.begin(SD_CS_PIN, sdSPI, 10000000)) {
    sdCardReady = false;
    return false;
  }

  sdCardReady = true;
  if (!ensureLogFileHeader()) {
    sdCardReady = false;
  }
  return sdCardReady;
}

bool writeLogEventToSD(const LogEvent &evt) {
  if (!sdCardReady) return false;

  File f = SD.open(LOG_FILE_PATH, FILE_APPEND);
  if (!f) {
    sdCardReady = false;
    return false;
  }

  char srcBuf[18];
  char destBuf[18];
  char bssidBuf[18];
  formatMac(evt.src, srcBuf);
  formatMac(evt.dest, destBuf);
  formatMac(evt.bssid, bssidBuf);

  f.print(evt.ms);
  f.print(',');
  f.print(evt.channel);
  f.print(',');
  f.print((evt.subtype == 0xC0) ? "deauth" : "disassoc");
  f.print(',');
  f.print("0x");
  if (evt.frameSubtypeHex < 0x10) f.print('0');
  f.print(evt.frameSubtypeHex, HEX);
  f.print(',');
  f.print(evt.rssi);
  f.print(',');
  f.print(evt.reasonCode);
  f.print(',');
  f.print(srcBuf);
  f.print(',');
  f.print(destBuf);
  f.print(',');
  f.println(bssidBuf);
  f.close();

  loggedEventsCount++;
  return true;
}

// ============================================================
// UI-thread event handling
// ============================================================
void handleDeauthEventOnUiThread() {
  setVisualState(STATE_DEAUTH_SEEN, 650);
  setLedMode(LED_MODE_ALERT, LED_ALERT_HOLD_MS);
}

void triggerSdFlash() {
  setVisualState(STATE_SD_LOGGING, sdFlashDurationMs);
  setLedMode(LED_MODE_SD_FLASH, LED_SD_FLASH_MS);
}

// ============================================================
// Promiscuous callback
// ============================================================
void wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  totalPackets++;
  packetsThisSample++;

  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = ppkt->payload;
  uint8_t frameControl0 = payload[0];

  if (frameControl0 == 0xA0 || frameControl0 == 0xC0) {
    deauthPackets++;
    if (pendingDeauthEvents < 20) pendingDeauthEvents++;

    if (sdLoggingEnabled && sdCardReady) {
      uint16_t reasonCode = (uint16_t)payload[24] | ((uint16_t)payload[25] << 8);
      enqueueLogEvent(frameControl0, frameControl0, reasonCode, ppkt->rx_ctrl.rssi, payload + 10, payload + 4, payload + 16, currentChannel);
    }
  }
}

// ============================================================
// Runtime updates
// ============================================================
void hopChannelIfNeeded() {
  if (scanMode != MODE_AUTO_SCAN) return;

  unsigned long now = millis();

  if (now - lastHopMs >= hopIntervalMs) {
    lastHopMs = now;
    currentChannel++;
    if (currentChannel > maxChannel) currentChannel = minChannel;
    applyCurrentChannel();
  }
}

void updateGraphIfNeeded() {
  unsigned long now = millis();

  if (now - lastGraphSampleMs >= graphSampleIntervalMs) {
    lastGraphSampleMs = now;

    uint16_t burst;
    noInterrupts();
    burst = packetsThisSample;
    packetsThisSample = 0;
    interrupts();

    lastActivityBurst = burst;
    uint8_t scaled = map(constrain(burst, 0, 80), 0, 80, 0, 100);
    pushGraphValue(scaled);
  }
}

void copyStatsForUi() {
  noInterrupts();
  totalPacketsUi = totalPackets;
  deauthPacketsUi = deauthPackets;
  droppedEventsUi = droppedLogEvents;
  interrupts();
}

void processPendingDeauthEvents() {
  uint8_t pending;
  noInterrupts();
  pending = pendingDeauthEvents;
  pendingDeauthEvents = 0;
  interrupts();

  while (pending > 0) {
    handleDeauthEventOnUiThread();
    pending--;
  }
}

void processSdLogQueue() {
  if (!sdLoggingEnabled || !sdCardReady) return;

  LogEvent evt;
  uint8_t writesThisLoop = 0;

  while (writesThisLoop < 4 && dequeueLogEvent(evt)) {
    if (writeLogEventToSD(evt)) {
      triggerSdFlash();
    } else {
      break;
    }
    writesThisLoop++;
  }
}

void handleStateTimeout() {
  if (stateUntilMs != 0 && millis() >= stateUntilMs) {
    stateUntilMs = 0;
    currentState = STATE_SCANNING;
  }
}

void handleTouch() {
  uint16_t rawTx = 0, rawTy = 0;
  bool touched = tft.getTouch(&rawTx, &rawTy);

  if (touched && !lastTouchState) {
    int tx = (SCREEN_W - 1) - (int)rawTx;  // flip X only
    int ty = (int)rawTy;                   // Y stays as-is

    if (tx < 0) tx = 0;
    if (tx > SCREEN_W - 1) tx = SCREEN_W - 1;
    if (ty < 0) ty = 0;
    if (ty > SCREEN_H - 1) ty = SCREEN_H - 1;

    if (millis() - lastTouchToggleMs > touchDebounceMs) {

      if (isPointInRect(tx, ty, TOUCH_MODE_X, TOUCH_MODE_Y, TOUCH_MODE_W, TOUCH_MODE_H)) {
        scanMode = (scanMode == MODE_AUTO_SCAN) ? MODE_MANUAL_SCAN : MODE_AUTO_SCAN;
        if (scanMode == MODE_AUTO_SCAN) {
          lastHopMs = millis();
        } else {
          applyCurrentChannel();
        }
        lastTouchToggleMs = millis();
      }
      else if (isPointInRect(tx, ty, TOUCH_CH_X, TOUCH_CH_Y, TOUCH_CH_W, TOUCH_CH_H)) {
        if (scanMode == MODE_MANUAL_SCAN) {
          stepManualChannel();
          lastTouchToggleMs = millis();
        }
      }
      else if (isPointInRect(tx, ty, TOUCH_HOP_X, TOUCH_HOP_Y, TOUCH_HOP_W, TOUCH_HOP_H)) {
        if (scanMode == MODE_AUTO_SCAN) {
          cycleHopPreset();
          lastTouchToggleMs = millis();
        }
      }
      else if (isPointInRect(tx, ty, TOUCH_SD_X, TOUCH_SD_Y, TOUCH_SD_W, TOUCH_SD_H)) {
        if (sdCardReady) {
          sdLoggingEnabled = !sdLoggingEnabled;
        }
        lastTouchToggleMs = millis();
      }
    }
  }

  lastTouchState = touched;
}

// ============================================================
// Static drawing
// ============================================================
void drawStaticHeaderBox() {
  tft.fillRect(0, 0, SCREEN_W, HEADER_H, COL_PANEL2);
  tft.drawFastHLine(0, HEADER_H - 1, SCREEN_W, COL_BORDER);
}

void drawStaticSpritePanel() {
  tft.fillRoundRect(SPRITE_PANEL_X, SPRITE_PANEL_Y, SPRITE_PANEL_W, SPRITE_PANEL_H, 8, COL_PANEL);
  tft.drawRoundRect(SPRITE_PANEL_X, SPRITE_PANEL_Y, SPRITE_PANEL_W, SPRITE_PANEL_H, 8, COL_BORDER);
}

void drawStaticSpriteInfoPanel() {
  tft.fillRoundRect(SPRITE_INFO_X, SPRITE_INFO_Y, SPRITE_INFO_W, SPRITE_INFO_H, 8, COL_PANEL);
  tft.drawRoundRect(SPRITE_INFO_X, SPRITE_INFO_Y, SPRITE_INFO_W, SPRITE_INFO_H, 8, COL_BORDER);
}

void drawStaticGraphPanel() {
  tft.fillRoundRect(GRAPH_X, GRAPH_Y, GRAPH_W, GRAPH_H, 8, COL_GRAPH_BG);
  tft.drawRoundRect(GRAPH_X, GRAPH_Y, GRAPH_W, GRAPH_H, 8, COL_BORDER);

  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(COL_TEXT, COL_GRAPH_BG);
  tft.drawString("Packet Activity", GRAPH_X + 8, GRAPH_Y + 5);

  for (int i = 0; i < 4; i++) {
    int gy = GRAPH_PLOT_Y + (i * GRAPH_PLOT_H / 4);
    tft.drawFastHLine(GRAPH_PLOT_X, gy, GRAPH_PLOT_W, COL_GRID);
  }
}

void drawStaticStatsPanel() {
  tft.fillRoundRect(STATS_X, STATS_Y, STATS_W, STATS_H, 8, COL_PANEL);
  tft.drawRoundRect(STATS_X, STATS_Y, STATS_W, STATS_H, 8, COL_BORDER);
}

void drawStaticTouchButtonFrame() {
  tft.drawRoundRect(TOUCH_SD_X, TOUCH_SD_Y, TOUCH_SD_W, TOUCH_SD_H, 8, COL_BORDER);
}

void drawStaticUI() {
  tft.fillScreen(COL_BG);
  drawStaticHeaderBox();
  drawStaticSpritePanel();
  drawStaticSpriteInfoPanel();
  drawStaticGraphPanel();
  drawStaticStatsPanel();
  drawStaticTouchButtonFrame();
}

// ============================================================
// Dynamic drawing
// ============================================================
void drawSdHeaderIcon() {
  if (!sdCardReady) {
    pushBrightImage(SD_ICON_X, SD_ICON_Y, SD_NO_WIDTH, SD_NO_HEIGHT, sd_no, sdSpriteBuffer, SD_SPRITE_BRIGHTNESS);
  } else if (sdLoggingEnabled) {
    pushBrightImage(SD_ICON_X, SD_ICON_Y, SD_ON_WIDTH, SD_ON_HEIGHT, sd_on, sdSpriteBuffer, SD_SPRITE_BRIGHTNESS);
  } else {
    pushBrightImage(SD_ICON_X, SD_ICON_Y, SD_OFF_WIDTH, SD_OFF_HEIGHT, sd_off, sdSpriteBuffer, SD_SPRITE_BRIGHTNESS);
  }
}

void updateHeader() {
  if (currentChannel == lastDrawnChannel &&
      sdLoggingEnabled == lastDrawnSdLoggingEnabled &&
      sdCardReady == lastDrawnSdCardReady &&
      deauthPacketsUi == lastDrawnDeauthPackets &&
      hopIntervalMs == lastDrawnHopInterval &&
      scanMode == lastDrawnScanMode) {
    return;
  }

  tft.fillRect(1, 1, SCREEN_W - 2, HEADER_H - 2, COL_PANEL2);

  tft.setTextDatum(TL_DATUM);
  tft.setTextColor((scanMode == MODE_MANUAL_SCAN) ? COL_LOG : COL_TEXT, COL_PANEL2);
  tft.drawString("CH " + String(currentChannel), 8, 6);

  tft.setTextColor((scanMode == MODE_AUTO_SCAN) ? COL_TEXT : COL_DIM, COL_PANEL2);
  tft.drawString("Hop " + String(hopIntervalMs) + "ms", 58, 6);

  drawSdHeaderIcon();

  tft.setTextColor(COL_TEXT, COL_PANEL2);
  tft.setTextDatum(TR_DATUM);
  tft.drawString("Deauth " + String(deauthPacketsUi), SCREEN_W - 8, 6);
  tft.setTextDatum(TL_DATUM);

  lastDrawnChannel = currentChannel;
  lastDrawnSdLoggingEnabled = sdLoggingEnabled;
  lastDrawnSdCardReady = sdCardReady;
  lastDrawnHopInterval = hopIntervalMs;
}

void updateSpritePanel() {
  if (currentState == lastDrawnState) return;

  tft.fillRoundRect(SPRITE_PANEL_X + 1, SPRITE_PANEL_Y + 1, SPRITE_PANEL_W - 2, SPRITE_PANEL_H - 2, 7, COL_PANEL);
  tft.drawRoundRect(SPRITE_PANEL_X, SPRITE_PANEL_Y, SPRITE_PANEL_W, SPRITE_PANEL_H, 8, COL_BORDER);

  switch (currentState) {
    case STATE_SCANNING:
      pushBrightImage(SPRITE_X, SPRITE_Y, NORM_PACKETS_WIDTH, NORM_PACKETS_HEIGHT, norm_packets, packetSpriteBuffer, PACKET_SPRITE_BRIGHTNESS);
      break;
    case STATE_DEAUTH_SEEN:
      pushBrightImage(SPRITE_X, SPRITE_Y, DEAUTH_PACKETS_WIDTH, DEAUTH_PACKETS_HEIGHT, deauth_packets, packetSpriteBuffer, PACKET_SPRITE_BRIGHTNESS);
      break;
    case STATE_SD_LOGGING:
      pushBrightImage(SPRITE_X, SPRITE_Y, PACKET_CAPTURE_WIDTH, PACKET_CAPTURE_HEIGHT, packet_capture, packetSpriteBuffer, PACKET_SPRITE_BRIGHTNESS);
      break;
  }

  lastDrawnState = currentState;
}

void updateSpriteInfoPanel() {
  if (scanMode == lastDrawnScanMode) return;

  tft.fillRoundRect(SPRITE_INFO_X + 1, SPRITE_INFO_Y + 1, SPRITE_INFO_W - 2, SPRITE_INFO_H - 2, 7, COL_PANEL);
  tft.drawRoundRect(SPRITE_INFO_X, SPRITE_INFO_Y, SPRITE_INFO_W, SPRITE_INFO_H, 8, COL_BORDER);

  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(COL_TEXT, COL_PANEL);
  tft.drawString("State:", SPRITE_INFO_X + 6, SPRITE_INFO_Y + 6);
  tft.drawString(stateLabel(), SPRITE_INFO_X + 6, SPRITE_INFO_Y + 22);

  lastDrawnScanMode = scanMode;
}

void updateGraphPanel() {
  bool changed = false;
  for (int i = 0; i < GRAPH_POINTS; i++) {
    if (graphData[i] != lastDrawnGraphData[i]) {
      changed = true;
      break;
    }
  }
  if (!changed) return;

  tft.fillRect(GRAPH_PLOT_X, GRAPH_PLOT_Y, GRAPH_PLOT_W, GRAPH_PLOT_H, COL_GRAPH_BG);

  for (int i = 0; i < 4; i++) {
    int gy = GRAPH_PLOT_Y + (i * GRAPH_PLOT_H / 4);
    tft.drawFastHLine(GRAPH_PLOT_X, gy, GRAPH_PLOT_W, COL_GRID);
  }

  int barW = GRAPH_PLOT_W / GRAPH_POINTS;
  if (barW < 1) barW = 1;

  int usedW = barW * GRAPH_POINTS;
  int startX = GRAPH_PLOT_X + ((GRAPH_PLOT_W - usedW) / 2);

  for (int i = 0; i < GRAPH_POINTS; i++) {
    int h = map(graphData[i], 0, 100, 0, GRAPH_PLOT_H - 2);
    int bx = startX + (i * barW);
    int by = GRAPH_PLOT_Y + GRAPH_PLOT_H - h;
    tft.fillRect(bx, by, barW, h, COL_ACCENT);
    lastDrawnGraphData[i] = graphData[i];
  }
}

void updateStatsPanel() {
  if (totalPacketsUi == lastDrawnTotalPackets &&
      deauthPacketsUi == lastDrawnDeauthPackets &&
      lastActivityBurst == lastDrawnBurst &&
      loggedEventsCount == lastDrawnLoggedEventsCount &&
      droppedEventsUi == lastDrawnDroppedEventsUi) {
    return;
  }

  tft.fillRoundRect(STATS_X + 1, STATS_Y + 1, STATS_W - 2, STATS_H - 2, 7, COL_PANEL);
  tft.drawRoundRect(STATS_X, STATS_Y, STATS_W, STATS_H, 8, COL_BORDER);

  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(COL_TEXT, COL_PANEL);
  tft.drawString("Packets: " + String(totalPacketsUi), STATS_X + 8, STATS_Y + 6);
  tft.drawString("Burst: " + String(lastActivityBurst), STATS_X + 8, STATS_Y + 21);
  tft.drawString("Deauth: " + String(deauthPacketsUi), STATS_X + 96, STATS_Y + 21);
  tft.drawString("Logged: " + String(loggedEventsCount), STATS_X + 8, STATS_Y + 36);
  tft.drawString("DropQ: " + String(droppedEventsUi), STATS_X + 96, STATS_Y + 36);

  lastDrawnTotalPackets = totalPacketsUi;
  lastDrawnDeauthPackets = deauthPacketsUi;
  lastDrawnBurst = lastActivityBurst;
  lastDrawnLoggedEventsCount = loggedEventsCount;
  lastDrawnDroppedEventsUi = droppedEventsUi;
}

void updateTouchButton() {
  uint16_t fill;
  const char* label;

  if (!sdCardReady) {
    fill = COL_WARN;
    label = "SD NOT READY  |  CHECK CARD/WIRING";
  } else if (sdLoggingEnabled) {
    fill = COL_BTN_ON;
    label = "SD LOGGING ON  |  TOUCH TO TOGGLE";
  } else {
    fill = COL_BTN_OFF;
    label = "SD LOGGING OFF |  TOUCH TO TOGGLE";
  }

  tft.fillRoundRect(TOUCH_SD_X + 1, TOUCH_SD_Y + 1, TOUCH_SD_W - 2, TOUCH_SD_H - 2, 8, fill);
  tft.drawRoundRect(TOUCH_SD_X, TOUCH_SD_Y, TOUCH_SD_W, TOUCH_SD_H, 8, COL_BORDER);

  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(TFT_WHITE, fill);
  tft.drawString(label, TOUCH_SD_X + TOUCH_SD_W / 2, TOUCH_SD_Y + TOUCH_SD_H / 2);
}

void updateDynamicUI() {
  updateHeader();
  updateSpritePanel();
  updateSpriteInfoPanel();
  updateGraphPanel();
  updateStatsPanel();
  updateTouchButton();
}

// ============================================================
// Wi-Fi sniffer setup
// ============================================================
void setupWifiSniffer() {
  WiFi.mode(WIFI_MODE_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  applyCurrentChannel();
  esp_wifi_set_promiscuous(true);
}

// ============================================================
// Setup
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, TFT_BACKLIGHT_ON);

  pinMode(R_PIN, OUTPUT);
  pinMode(G_PIN, OUTPUT);
  pinMode(B_PIN, OUTPUT);
  setLedMode(LED_MODE_SCAN);

  tft.init();
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);
  delay(100);

  drawSplashScreen();

  for (int i = 0; i < GRAPH_POINTS; i++) {
    graphData[i] = 0;
    lastDrawnGraphData[i] = 255;
  }

  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.drawString("Starting Deauth Sluth...", SCREEN_W / 2, SCREEN_H / 2 + 88);
  delay(400);

  initSDCard();

  drawStaticUI();

  lastDrawnState = (ScannerVisualState)255;
  lastDrawnChannel = 255;
  lastDrawnScanMode = (ScanMode)255;
  lastDrawnSdLoggingEnabled = !sdLoggingEnabled;
  lastDrawnSdCardReady = !sdCardReady;
  lastDrawnHopInterval = 0xFFFFFFFF;
  lastDrawnTotalPackets = 0xFFFFFFFF;
  lastDrawnDeauthPackets = 0xFFFFFFFF;
  lastDrawnBurst = 0xFFFF;
  lastDrawnLoggedEventsCount = 0xFFFFFFFF;
  lastDrawnDroppedEventsUi = 0xFFFFFFFF;

  copyStatsForUi();
  updateDynamicUI();

  setupWifiSniffer();
}

// ============================================================
// Loop
// ============================================================
void loop() {
  handleTouch();
  processPendingDeauthEvents();
  processSdLogQueue();
  updateGraphIfNeeded();
  hopChannelIfNeeded();
  handleStateTimeout();
  updateLedState();
  copyStatsForUi();
  updateDynamicUI();
  delay(35);
}
