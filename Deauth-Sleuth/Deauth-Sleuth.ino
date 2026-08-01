/*
  ============================================================
  Deauth Sleuth v1.1
  Board: ESP32-2432S028R
  Framework: Arduino / ESP32 core 2.0.10
  Display: 320x240 TFT using TFT_eSPI
  Touch: TFT_eSPI getTouch()
  Created by ATOMNFT

  Deauth Sleuth is a touchscreen ESP32 Wi-Fi monitoring tool
  built for the ESP32-2432S028R. It scans nearby wireless
  traffic, watches for deauthentication and disassociation
  activity, monitors for possible Evil Twin behavior, and
  presents live status through custom graphics, alerts, touch
  controls, RGB LED feedback, and optional SD logging.

  Features include:
  - Auto Scan and Manual Scan modes
  - Touch control for scan mode, channel, hop speed, and SD logging
  - Manual channel selection from the CH area
  - Adjustable channel-hop presets in Auto Scan mode
  - Splash screen and custom packet/status artwork
  - Live packet graph and session statistics
  - SD card status icons with on-screen logging toggle
  - Expanded CSV logging for deauth/disassoc events
  - Passive Evil Twin monitoring for duplicate SSID anomalies
  - Separate Evil Twin CSV logging with risk details
  - Evil Twin alert and capture artwork
  - RGB LED feedback for scanning, alerts, and SD writes
  - User-adjustable settings stored in config.h
  - Low, Balanced, and High alert sensitivity profiles

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
#include "config.h"

// ============================================================
// Sprites
// ============================================================
#include "norm-packets.h"
#include "deauth-packets.h"
#include "packet-capture.h"
#include "evil-packets.h"
#include "evil-capture.h"
#include "sd-no.h"
#include "sd-off.h"
#include "sd-on.h"
#include "splash.h"

TFT_eSPI tft = TFT_eSPI();

// Forward declarations for Arduino auto-generated prototypes
struct LogEvent;
struct ApObservation;
struct ApRecord;
struct EvilTwinLogEvent;




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




// Scratch buffers used for brightness-adjusted RGB565 drawing
uint16_t packetSpriteBuffer[PACKET_SPRITE_BUFFER_W * PACKET_SPRITE_BUFFER_H];
uint16_t sdSpriteBuffer[SD_SPRITE_BUFFER_W * SD_SPRITE_BUFFER_H];


SPIClass sdSPI(VSPI);

bool sdCardReady = false;
bool sdLoggingEnabled = false;
bool lastDrawnSdLoggingEnabled = false;
bool lastDrawnSdCardReady = false;



// ============================================================
// Visual states
// ============================================================
enum ScannerVisualState {
  STATE_SCANNING,
  STATE_DEAUTH_SEEN,
  STATE_SD_LOGGING,
  STATE_EVIL_TWIN_SEEN,
  STATE_EVIL_TWIN_SD_LOGGING
};

ScannerVisualState currentState = STATE_SCANNING;
ScannerVisualState lastDrawnState = (ScannerVisualState)255;
unsigned long stateUntilMs = 0;
unsigned long sdFlashDurationMs = SD_FLASH_DURATION_MS;

// ============================================================
// Scan mode / hopping
// ============================================================
enum ScanMode {
  MODE_AUTO_SCAN,
  MODE_MANUAL_SCAN
};

ScanMode scanMode = MODE_AUTO_SCAN;
ScanMode lastDrawnScanMode = (ScanMode)255;

uint8_t currentChannel = DEFAULT_CHANNEL;
uint8_t lastDrawnChannel = 255;
unsigned long lastHopMs = 0;

uint8_t hopPresetIndex = DEFAULT_HOP_PRESET_INDEX;
unsigned long hopIntervalMs = HOP_PRESETS[hopPresetIndex];
unsigned long lastDrawnHopInterval = 0xFFFFFFFF;

// ============================================================
// Packet activity
// ============================================================
volatile uint32_t totalPackets = 0;
volatile uint32_t deauthPackets = 0;
volatile uint16_t packetsThisSample = 0;
volatile uint8_t pendingDeauthEvents = 0;

// Deauth/disassoc CSV logging still records every detected frame.
// These values only control when the visual and RGB alert fires.
unsigned long deauthBurstWindowStartMs = 0;
uint16_t deauthBurstEventCount = 0;

uint32_t totalPacketsUi = 0;
uint32_t deauthPacketsUi = 0;
uint16_t lastActivityBurst = 0;

uint32_t lastDrawnTotalPackets = 0xFFFFFFFF;
uint32_t lastDrawnDeauthPackets = 0xFFFFFFFF;
uint16_t lastDrawnBurst = 0xFFFF;

// ============================================================
// Passive Evil Twin detector
// ============================================================
// The callback only queues compact beacon/probe-response observations.
// SSID comparison, table maintenance, and risk scoring happen in loop().
enum EvilTwinState {
  TWIN_LEARNING,
  TWIN_CLEAR,
  TWIN_SUSPICIOUS,
  TWIN_HIGH_RISK
};

enum ApSecurity {
  AP_SEC_OPEN,
  AP_SEC_WEP,
  AP_SEC_WPA,
  AP_SEC_WPA2,
  AP_SEC_WPA3
};

struct ApObservation {
  char ssid[33];
  uint8_t ssidLength;
  uint8_t bssid[6];
  uint8_t channel;
  int8_t rssi;
  uint8_t security;
  uint32_t seenMs;
};

struct ApRecord {
  bool used;
  char ssid[33];
  uint8_t ssidLength;
  uint8_t bssid[6];
  uint8_t channel;
  int8_t rssi;
  uint8_t security;
  uint32_t firstSeenMs;
  uint32_t lastSeenMs;
  uint16_t seenCount;
};

volatile ApObservation apObservationQueue[AP_OBSERVATION_QUEUE_SIZE];
volatile uint8_t apObservationHead = 0;
volatile uint8_t apObservationTail = 0;
volatile uint32_t droppedApObservations = 0;

ApRecord apTable[AP_TABLE_SIZE];


// When the detector is clear, briefly show its status before returning
// the panel to the normal Auto Scan / Manual Scan display.

unsigned long evilTwinLearningStartMs = 0;
EvilTwinState evilTwinState = TWIN_LEARNING;
EvilTwinState lastDrawnEvilTwinState = (EvilTwinState)255;
uint8_t evilTwinRiskScore = 0;

unsigned long lastTwinClearDisplayMs = 0;
bool showingTwinClearStatus = false;
bool lastDrawnShowingTwinStatus = false;

// Risk reasons are stored as a bit mask so the CSV can explain why
// a duplicate SSID was considered suspicious.
enum EvilTwinReasonFlags {
  TWIN_REASON_SECURITY_MISMATCH = 0x01,
  TWIN_REASON_DIFFERENT_OUI     = 0x02,
  TWIN_REASON_DIFFERENT_CHANNEL = 0x04,
  TWIN_REASON_RSSI_DIFFERENCE   = 0x08,
  TWIN_REASON_NEW_AFTER_LEARN   = 0x10,
  TWIN_REASON_MULTI_BSSID       = 0x20
};

struct EvilTwinLogEvent {
  uint32_t ms;
  char ssid[33];
  uint8_t riskScore;
  uint8_t reasonFlags;
  uint8_t knownBssid[6];
  uint8_t suspectBssid[6];
  uint8_t knownChannel;
  uint8_t suspectChannel;
  int8_t knownRssi;
  int8_t suspectRssi;
  uint8_t knownSecurity;
  uint8_t suspectSecurity;
};

EvilTwinLogEvent evilTwinLogQueue[EVIL_TWIN_LOG_QUEUE_SIZE];
uint8_t evilTwinLogHead = 0;
uint8_t evilTwinLogTail = 0;
uint32_t droppedEvilTwinLogEvents = 0;
uint32_t loggedEvilTwinEventsCount = 0;

// Prevent the same persistent pair from being logged every loop.
uint8_t lastLoggedTwinBssidA[6] = {0};
uint8_t lastLoggedTwinBssidB[6] = {0};
uint8_t lastLoggedTwinRiskScore = 0;
unsigned long lastEvilTwinLogMs = 0;

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
  if (hopPresetIndex >= HOP_PRESET_COUNT) hopPresetIndex = 0;
  hopIntervalMs = HOP_PRESETS[hopPresetIndex];
}

void stepManualChannel() {
  currentChannel++;
  if (currentChannel > MAX_CHANNEL) currentChannel = MIN_CHANNEL;
  applyCurrentChannel();
}

const char* evilTwinLabel() {
  switch (evilTwinState) {
    case TWIN_LEARNING:   return "Learning";
    case TWIN_CLEAR:      return "Clear";
    case TWIN_SUSPICIOUS: return "Sus";
    case TWIN_HIGH_RISK:  return "HIGH";
  }
  return "?";
}

uint16_t evilTwinStatusColor() {
  switch (evilTwinState) {
    case TWIN_LEARNING:   return COL_LOG;
    case TWIN_CLEAR:      return COL_ACCENT;
    case TWIN_SUSPICIOUS: return COL_WARN;
    case TWIN_HIGH_RISK:  return COL_ALERT;
  }
  return COL_TEXT;
}

bool shouldShowTwinStatus() {
  unsigned long now = millis();

  // Keep learning and active warnings visible continuously.
  if (evilTwinState == TWIN_LEARNING ||
      evilTwinState == TWIN_SUSPICIOUS ||
      evilTwinState == TWIN_HIGH_RISK) {
    showingTwinClearStatus = false;
    return true;
  }

  // When clear, show a short heartbeat at the selected interval.
  if (!showingTwinClearStatus &&
      now - lastTwinClearDisplayMs >= TWIN_CLEAR_SHOW_INTERVAL_MS) {
    showingTwinClearStatus = true;
    lastTwinClearDisplayMs = now;
  }

  if (showingTwinClearStatus) {
    if (now - lastTwinClearDisplayMs < TWIN_CLEAR_SHOW_TIME_MS) {
      return true;
    }

    showingTwinClearStatus = false;
  }

  return false;
}

bool macEquals(const uint8_t* a, const uint8_t* b) {
  for (uint8_t i = 0; i < 6; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool ouiEquals(const uint8_t* a, const uint8_t* b) {
  return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
}

bool ssidEquals(const char* a, uint8_t aLen, const char* b, uint8_t bLen) {
  if (aLen != bLen) return false;
  for (uint8_t i = 0; i < aLen; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

uint8_t parseApSecurity(const uint8_t* payload, uint16_t packetLength, uint16_t ieStart) {
  if (packetLength < 36) return AP_SEC_OPEN;

  uint16_t capability = (uint16_t)payload[34] | ((uint16_t)payload[35] << 8);
  bool privacy = (capability & 0x0010) != 0;
  bool hasWpa = false;
  bool hasRsn = false;
  bool hasWpa3Akm = false;

  uint16_t pos = ieStart;
  while (pos + 2 <= packetLength) {
    uint8_t id = payload[pos];
    uint8_t len = payload[pos + 1];
    uint16_t next = pos + 2 + len;
    if (next > packetLength) break;

    if (id == 48) {
      hasRsn = true;

      // Look for WPA3 SAE / FT-SAE AKM suite types inside the RSN IE.
      for (uint16_t i = pos + 2; i + 3 < next; i++) {
        if (payload[i] == 0x00 &&
            payload[i + 1] == 0x0F &&
            payload[i + 2] == 0xAC &&
            (payload[i + 3] == 0x08 || payload[i + 3] == 0x09)) {
          hasWpa3Akm = true;
          break;
        }
      }
    } else if (id == 221 && len >= 4) {
      if (payload[pos + 2] == 0x00 &&
          payload[pos + 3] == 0x50 &&
          payload[pos + 4] == 0xF2 &&
          payload[pos + 5] == 0x01) {
        hasWpa = true;
      }
    }

    pos = next;
  }

  if (hasWpa3Akm) return AP_SEC_WPA3;
  if (hasRsn) return AP_SEC_WPA2;
  if (hasWpa) return AP_SEC_WPA;
  if (privacy) return AP_SEC_WEP;
  return AP_SEC_OPEN;
}

bool extractApObservation(const wifi_promiscuous_pkt_t* ppkt, ApObservation &obs) {
  const uint8_t* payload = ppkt->payload;
  uint16_t packetLength = ppkt->rx_ctrl.sig_len;

  // Beacon and probe-response frames both have a 24-byte management
  // header followed by 12 bytes of fixed parameters.
  if (packetLength < 38) return false;

  uint8_t frameControl0 = payload[0];
  if (frameControl0 != 0x80 && frameControl0 != 0x50) return false;

  const uint16_t ieStart = 36;
  uint16_t pos = ieStart;
  bool foundSsid = false;
  uint8_t advertisedChannel = 0;

  obs.ssidLength = 0;
  obs.ssid[0] = '\0';

  while (pos + 2 <= packetLength) {
    uint8_t id = payload[pos];
    uint8_t len = payload[pos + 1];
    uint16_t next = pos + 2 + len;
    if (next > packetLength) break;

    if (id == 0 && !foundSsid) {
      // Ignore hidden/blank SSIDs for duplicate-name detection.
      if (len == 0) return false;

      obs.ssidLength = (len > 32) ? 32 : len;
      for (uint8_t i = 0; i < obs.ssidLength; i++) {
        char c = (char)payload[pos + 2 + i];
        obs.ssid[i] = (c >= 32 && c <= 126) ? c : '?';
      }
      obs.ssid[obs.ssidLength] = '\0';
      foundSsid = true;
    } else if (id == 3 && len >= 1) {
      advertisedChannel = payload[pos + 2];
    }

    pos = next;
  }

  if (!foundSsid) return false;

  for (uint8_t i = 0; i < 6; i++) {
    obs.bssid[i] = payload[16 + i];
  }

  obs.channel = advertisedChannel;
  if (obs.channel < MIN_CHANNEL || obs.channel > MAX_CHANNEL) {
    obs.channel = currentChannel;
  }

  obs.rssi = ppkt->rx_ctrl.rssi;
  obs.security = parseApSecurity(payload, packetLength, ieStart);
  obs.seenMs = millis();
  return true;
}

bool enqueueApObservation(const ApObservation &obs) {
  noInterrupts();
  uint8_t nextHead = (apObservationHead + 1) % AP_OBSERVATION_QUEUE_SIZE;

  if (nextHead == apObservationTail) {
    droppedApObservations++;
    interrupts();
    return false;
  }

  apObservationQueue[apObservationHead].ssidLength = obs.ssidLength;
  for (uint8_t i = 0; i <= obs.ssidLength; i++) {
    apObservationQueue[apObservationHead].ssid[i] = obs.ssid[i];
  }
  for (uint8_t i = 0; i < 6; i++) {
    apObservationQueue[apObservationHead].bssid[i] = obs.bssid[i];
  }
  apObservationQueue[apObservationHead].channel = obs.channel;
  apObservationQueue[apObservationHead].rssi = obs.rssi;
  apObservationQueue[apObservationHead].security = obs.security;
  apObservationQueue[apObservationHead].seenMs = obs.seenMs;

  apObservationHead = nextHead;
  interrupts();
  return true;
}

bool dequeueApObservation(ApObservation &obs) {
  bool hasItem = false;

  noInterrupts();
  if (apObservationTail != apObservationHead) {
    obs.ssidLength = apObservationQueue[apObservationTail].ssidLength;
    for (uint8_t i = 0; i <= obs.ssidLength; i++) {
      obs.ssid[i] = apObservationQueue[apObservationTail].ssid[i];
    }
    for (uint8_t i = 0; i < 6; i++) {
      obs.bssid[i] = apObservationQueue[apObservationTail].bssid[i];
    }
    obs.channel = apObservationQueue[apObservationTail].channel;
    obs.rssi = apObservationQueue[apObservationTail].rssi;
    obs.security = apObservationQueue[apObservationTail].security;
    obs.seenMs = apObservationQueue[apObservationTail].seenMs;

    apObservationTail = (apObservationTail + 1) % AP_OBSERVATION_QUEUE_SIZE;
    hasItem = true;
  }
  interrupts();

  return hasItem;
}

int findApRecordByBssid(const uint8_t* bssid) {
  for (uint8_t i = 0; i < AP_TABLE_SIZE; i++) {
    if (apTable[i].used && macEquals(apTable[i].bssid, bssid)) {
      return i;
    }
  }
  return -1;
}

int findFreeOrOldestApRecord() {
  int oldestIndex = 0;
  uint32_t oldestSeen = 0xFFFFFFFF;

  for (uint8_t i = 0; i < AP_TABLE_SIZE; i++) {
    if (!apTable[i].used) return i;

    if (apTable[i].lastSeenMs < oldestSeen) {
      oldestSeen = apTable[i].lastSeenMs;
      oldestIndex = i;
    }
  }

  return oldestIndex;
}

void storeApObservation(const ApObservation &obs) {
  int index = findApRecordByBssid(obs.bssid);

  if (index < 0) {
    index = findFreeOrOldestApRecord();
    apTable[index].used = true;
    apTable[index].firstSeenMs = obs.seenMs;
    apTable[index].seenCount = 0;
  }

  apTable[index].ssidLength = obs.ssidLength;
  for (uint8_t i = 0; i <= obs.ssidLength; i++) {
    apTable[index].ssid[i] = obs.ssid[i];
  }
  for (uint8_t i = 0; i < 6; i++) {
    apTable[index].bssid[i] = obs.bssid[i];
  }

  apTable[index].channel = obs.channel;
  apTable[index].rssi = obs.rssi;
  apTable[index].security = obs.security;
  apTable[index].lastSeenMs = obs.seenMs;
  if (apTable[index].seenCount < 0xFFFF) apTable[index].seenCount++;
}

void expireOldApRecords(uint32_t now) {
  for (uint8_t i = 0; i < AP_TABLE_SIZE; i++) {
    if (apTable[i].used && now - apTable[i].lastSeenMs > AP_RECORD_TTL_MS) {
      apTable[i].used = false;
    }
  }
}


const char* apSecurityLabel(uint8_t security) {
  switch (security) {
    case AP_SEC_OPEN: return "OPEN";
    case AP_SEC_WEP:  return "WEP";
    case AP_SEC_WPA:  return "WPA";
    case AP_SEC_WPA2: return "WPA2";
    case AP_SEC_WPA3: return "WPA3";
  }
  return "UNKNOWN";
}

void buildEvilTwinReasonText(uint8_t flags, char* output, size_t outputSize) {
  if (outputSize == 0) return;
  output[0] = '\0';

  struct ReasonName {
    uint8_t flag;
    const char* name;
  };

  const ReasonName reasons[] = {
    {TWIN_REASON_SECURITY_MISMATCH, "security_mismatch"},
    {TWIN_REASON_DIFFERENT_OUI,     "different_oui"},
    {TWIN_REASON_DIFFERENT_CHANNEL, "different_channel"},
    {TWIN_REASON_RSSI_DIFFERENCE,   "rssi_difference"},
    {TWIN_REASON_NEW_AFTER_LEARN,   "new_after_learning"},
    {TWIN_REASON_MULTI_BSSID,       "multiple_bssids"}
  };

  bool first = true;
  for (uint8_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
    if ((flags & reasons[i].flag) == 0) continue;

    if (!first) {
      strncat(output, "|", outputSize - strlen(output) - 1);
    }
    strncat(output, reasons[i].name, outputSize - strlen(output) - 1);
    first = false;
  }

  if (first) {
    strncpy(output, "duplicate_ssid", outputSize - 1);
    output[outputSize - 1] = '\0';
  }
}

bool sameTwinPair(const uint8_t* a1, const uint8_t* b1,
                  const uint8_t* a2, const uint8_t* b2) {
  return (macEquals(a1, a2) && macEquals(b1, b2)) ||
         (macEquals(a1, b2) && macEquals(b1, a2));
}

bool enqueueEvilTwinLogEvent(const ApRecord &known,
                             const ApRecord &suspect,
                             uint8_t riskScore,
                             uint8_t reasonFlags) {
  uint8_t nextHead = (evilTwinLogHead + 1) % EVIL_TWIN_LOG_QUEUE_SIZE;
  if (nextHead == evilTwinLogTail) {
    droppedEvilTwinLogEvents++;
    return false;
  }

  EvilTwinLogEvent &evt = evilTwinLogQueue[evilTwinLogHead];
  evt.ms = millis();
  evt.riskScore = riskScore;
  evt.reasonFlags = reasonFlags;
  evt.knownChannel = known.channel;
  evt.suspectChannel = suspect.channel;
  evt.knownRssi = known.rssi;
  evt.suspectRssi = suspect.rssi;
  evt.knownSecurity = known.security;
  evt.suspectSecurity = suspect.security;

  strncpy(evt.ssid, known.ssid, sizeof(evt.ssid) - 1);
  evt.ssid[sizeof(evt.ssid) - 1] = '\0';

  for (uint8_t i = 0; i < 6; i++) {
    evt.knownBssid[i] = known.bssid[i];
    evt.suspectBssid[i] = suspect.bssid[i];
  }

  evilTwinLogHead = nextHead;
  return true;
}

bool dequeueEvilTwinLogEvent(EvilTwinLogEvent &evt) {
  if (evilTwinLogTail == evilTwinLogHead) return false;

  evt = evilTwinLogQueue[evilTwinLogTail];
  evilTwinLogTail = (evilTwinLogTail + 1) % EVIL_TWIN_LOG_QUEUE_SIZE;
  return true;
}

void queueEvilTwinAlertIfNeeded(const ApRecord &known,
                                const ApRecord &suspect,
                                uint8_t riskScore,
                                uint8_t reasonFlags) {
  if (!sdLoggingEnabled || !sdCardReady) return;

  unsigned long now = millis();
  bool samePair = sameTwinPair(
    known.bssid, suspect.bssid,
    lastLoggedTwinBssidA, lastLoggedTwinBssidB
  );

  bool strongerRisk = riskScore > lastLoggedTwinRiskScore;
  bool relogTimeReached = now - lastEvilTwinLogMs >= EVIL_TWIN_RELOG_INTERVAL_MS;

  if (samePair && !strongerRisk && !relogTimeReached) return;

  if (enqueueEvilTwinLogEvent(known, suspect, riskScore, reasonFlags)) {
    for (uint8_t i = 0; i < 6; i++) {
      lastLoggedTwinBssidA[i] = known.bssid[i];
      lastLoggedTwinBssidB[i] = suspect.bssid[i];
    }
    lastLoggedTwinRiskScore = riskScore;
    lastEvilTwinLogMs = now;
  }
}

void evaluateEvilTwinRisk() {
  uint32_t now = millis();

  if (now - evilTwinLearningStartMs < EVIL_TWIN_LEARNING_MS) {
    evilTwinRiskScore = 0;
    evilTwinState = TWIN_LEARNING;
    return;
  }

  uint8_t highestScore = 0;
  uint8_t highestReasonFlags = 0;
  int8_t bestKnownIndex = -1;
  int8_t bestSuspectIndex = -1;

  for (uint8_t i = 0; i < AP_TABLE_SIZE; i++) {
    if (!apTable[i].used) continue;

    uint8_t sameSsidCount = 1;

    for (uint8_t j = i + 1; j < AP_TABLE_SIZE; j++) {
      if (!apTable[j].used) continue;
      if (!ssidEquals(apTable[i].ssid, apTable[i].ssidLength,
                      apTable[j].ssid, apTable[j].ssidLength)) {
        continue;
      }

      sameSsidCount++;
      uint8_t score = 0;
      uint8_t reasonFlags = 0;

      if (apTable[i].security != apTable[j].security) {
        score += TWIN_SCORE_SECURITY_MISMATCH;
        reasonFlags |= TWIN_REASON_SECURITY_MISMATCH;
      }

      if (!ouiEquals(apTable[i].bssid, apTable[j].bssid)) {
        score += TWIN_SCORE_DIFFERENT_OUI;
        reasonFlags |= TWIN_REASON_DIFFERENT_OUI;
      }

      if (apTable[i].channel != apTable[j].channel) {
        score += TWIN_SCORE_DIFFERENT_CHANNEL;
        reasonFlags |= TWIN_REASON_DIFFERENT_CHANNEL;
      }

      int rssiDifference = (int)apTable[i].rssi - (int)apTable[j].rssi;
      if (rssiDifference < 0) rssiDifference = -rssiDifference;
      if (rssiDifference >= EVIL_TWIN_RSSI_DIFFERENCE_DB) {
        score += TWIN_SCORE_RSSI_DIFFERENCE;
        reasonFlags |= TWIN_REASON_RSSI_DIFFERENCE;
      }

      // A duplicate first seen after the learning window is more suspicious.
      if (apTable[i].firstSeenMs >= evilTwinLearningStartMs + EVIL_TWIN_LEARNING_MS ||
          apTable[j].firstSeenMs >= evilTwinLearningStartMs + EVIL_TWIN_LEARNING_MS) {
        score += TWIN_SCORE_NEW_AFTER_LEARNING;
        reasonFlags |= TWIN_REASON_NEW_AFTER_LEARN;
      }

      if (sameSsidCount >= 3) {
        score += TWIN_SCORE_MULTIPLE_BSSIDS;
        reasonFlags |= TWIN_REASON_MULTI_BSSID;
      }

      if (score > highestScore) {
        highestScore = score;
        highestReasonFlags = reasonFlags;

        // Treat the AP seen first as the established/known record.
        if (apTable[i].firstSeenMs <= apTable[j].firstSeenMs) {
          bestKnownIndex = i;
          bestSuspectIndex = j;
        } else {
          bestKnownIndex = j;
          bestSuspectIndex = i;
        }
      }
    }
  }

  EvilTwinState previousState = evilTwinState;
  evilTwinRiskScore = highestScore;

  if (highestScore >= EVIL_TWIN_HIGH_RISK_SCORE) {
    evilTwinState = TWIN_HIGH_RISK;
  } else if (highestScore >= EVIL_TWIN_SUSPICIOUS_SCORE) {
    evilTwinState = TWIN_SUSPICIOUS;
  } else {
    evilTwinState = TWIN_CLEAR;
  }

  if ((evilTwinState == TWIN_SUSPICIOUS ||
       evilTwinState == TWIN_HIGH_RISK) &&
      bestKnownIndex >= 0 &&
      bestSuspectIndex >= 0) {

    // Display the Evil Twin warning art when a new alert appears or
    // when its severity increases.
    if (previousState != evilTwinState ||
        evilTwinState == TWIN_HIGH_RISK) {
      setVisualState(STATE_EVIL_TWIN_SEEN, EVIL_TWIN_VISUAL_DURATION_MS);
      setLedMode(LED_MODE_ALERT, LED_ALERT_HOLD_MS);
    }

    queueEvilTwinAlertIfNeeded(
      apTable[bestKnownIndex],
      apTable[bestSuspectIndex],
      highestScore,
      highestReasonFlags
    );
  }
}

void processApObservationQueue() {
  ApObservation obs;
  uint8_t processed = 0;

  while (processed < AP_OBSERVATIONS_PER_LOOP && dequeueApObservation(obs)) {
    storeApObservation(obs);
    processed++;
  }

  expireOldApRecords(millis());
  evaluateEvilTwinRisk();
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

bool ensureEvilTwinLogFileHeader() {
  if (!sdCardReady) return false;

  if (!SD.exists(EVIL_TWIN_LOG_FILE_PATH)) {
    File f = SD.open(EVIL_TWIN_LOG_FILE_PATH, FILE_WRITE);
    if (!f) return false;
    f.println("millis,ssid,risk_score,state,reasons,known_bssid,suspect_bssid,known_channel,suspect_channel,known_rssi,suspect_rssi,known_security,suspect_security");
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
  if (!ensureLogFileHeader() || !ensureEvilTwinLogFileHeader()) {
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

void writeCsvQuoted(File &f, const char* value) {
  f.print('"');
  while (*value) {
    if (*value == '"') f.print('"');
    f.print(*value);
    value++;
  }
  f.print('"');
}

bool writeEvilTwinEventToSD(const EvilTwinLogEvent &evt) {
  if (!sdCardReady) return false;

  File f = SD.open(EVIL_TWIN_LOG_FILE_PATH, FILE_APPEND);
  if (!f) {
    sdCardReady = false;
    return false;
  }

  char knownBssidBuf[18];
  char suspectBssidBuf[18];
  char reasonText[128];

  formatMac(evt.knownBssid, knownBssidBuf);
  formatMac(evt.suspectBssid, suspectBssidBuf);
  buildEvilTwinReasonText(evt.reasonFlags, reasonText, sizeof(reasonText));

  f.print(evt.ms);
  f.print(',');
  writeCsvQuoted(f, evt.ssid);
  f.print(',');
  f.print(evt.riskScore);
  f.print(',');
  f.print((evt.riskScore >= EVIL_TWIN_HIGH_RISK_SCORE) ? "high" : "suspicious");
  f.print(',');
  writeCsvQuoted(f, reasonText);
  f.print(',');
  f.print(knownBssidBuf);
  f.print(',');
  f.print(suspectBssidBuf);
  f.print(',');
  f.print(evt.knownChannel);
  f.print(',');
  f.print(evt.suspectChannel);
  f.print(',');
  f.print(evt.knownRssi);
  f.print(',');
  f.print(evt.suspectRssi);
  f.print(',');
  f.print(apSecurityLabel(evt.knownSecurity));
  f.print(',');
  f.println(apSecurityLabel(evt.suspectSecurity));
  f.close();

  loggedEvilTwinEventsCount++;
  return true;
}

// ============================================================
// UI-thread event handling
// ============================================================
void handleDeauthEventOnUiThread() {
  setVisualState(STATE_DEAUTH_SEEN, DEAUTH_VISUAL_DURATION_MS);
  setLedMode(LED_MODE_ALERT, LED_ALERT_HOLD_MS);
}

void triggerSdFlash() {
  setVisualState(STATE_SD_LOGGING, sdFlashDurationMs);
  setLedMode(LED_MODE_SD_FLASH, LED_SD_FLASH_MS);
}

void triggerEvilTwinSdFlash() {
  setVisualState(STATE_EVIL_TWIN_SD_LOGGING, sdFlashDurationMs);
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

  if (frameControl0 == 0x80 || frameControl0 == 0x50) {
    ApObservation observation;
    if (extractApObservation(ppkt, observation)) {
      enqueueApObservation(observation);
    }
  }

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
    if (currentChannel > MAX_CHANNEL) currentChannel = MIN_CHANNEL;
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

  if (pending == 0) return;

  unsigned long now = millis();

  // Begin a new burst window after the previous one expires.
  if (deauthBurstWindowStartMs == 0 ||
      now - deauthBurstWindowStartMs > DEAUTH_BURST_WINDOW_MS) {
    deauthBurstWindowStartMs = now;
    deauthBurstEventCount = 0;
  }

  deauthBurstEventCount += pending;

  // Trigger one alert when the selected profile threshold is met.
  // Resetting the window prevents one sustained burst from retriggering
  // the UI on every loop pass.
  if (deauthBurstEventCount >= DEAUTH_BURST_THRESHOLD) {
    handleDeauthEventOnUiThread();
    deauthBurstWindowStartMs = now;
    deauthBurstEventCount = 0;
  }
}

void processSdLogQueue() {
  if (!sdLoggingEnabled || !sdCardReady) return;

  LogEvent evt;
  uint8_t writesThisLoop = 0;

  while (writesThisLoop < DEAUTH_SD_WRITES_PER_LOOP && dequeueLogEvent(evt)) {
    if (writeLogEventToSD(evt)) {
      triggerSdFlash();
    } else {
      break;
    }
    writesThisLoop++;
  }

  EvilTwinLogEvent twinEvt;
  uint8_t twinWritesThisLoop = 0;

  while (twinWritesThisLoop < EVIL_TWIN_SD_WRITES_PER_LOOP && dequeueEvilTwinLogEvent(twinEvt)) {
    if (writeEvilTwinEventToSD(twinEvt)) {
      triggerEvilTwinSdFlash();
    } else {
      break;
    }
    twinWritesThisLoop++;
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
    case STATE_EVIL_TWIN_SEEN:
      pushBrightImage(SPRITE_X, SPRITE_Y, EVIL_PACKETS_WIDTH, EVIL_PACKETS_HEIGHT, evil_packets, packetSpriteBuffer, PACKET_SPRITE_BRIGHTNESS);
      break;
    case STATE_EVIL_TWIN_SD_LOGGING:
      pushBrightImage(SPRITE_X, SPRITE_Y, EVIL_CAPTURE_WIDTH, EVIL_CAPTURE_HEIGHT, evil_capture, packetSpriteBuffer, PACKET_SPRITE_BRIGHTNESS);
      break;
  }

  lastDrawnState = currentState;
}

void updateSpriteInfoPanel() {
  bool showTwinStatus = shouldShowTwinStatus();

  if (scanMode == lastDrawnScanMode &&
      evilTwinState == lastDrawnEvilTwinState &&
      showTwinStatus == lastDrawnShowingTwinStatus) {
    return;
  }

  tft.fillRoundRect(SPRITE_INFO_X + 1, SPRITE_INFO_Y + 1, SPRITE_INFO_W - 2, SPRITE_INFO_H - 2, 7, COL_PANEL);
  tft.drawRoundRect(SPRITE_INFO_X, SPRITE_INFO_Y, SPRITE_INFO_W, SPRITE_INFO_H, 8, COL_BORDER);

  tft.setTextDatum(TL_DATUM);

  if (showTwinStatus) {
    tft.setTextColor(evilTwinStatusColor(), COL_PANEL);
    tft.drawString("Evil-Twin:", SPRITE_INFO_X + 6, SPRITE_INFO_Y + 6);
    tft.drawString(evilTwinLabel(), SPRITE_INFO_X + 6, SPRITE_INFO_Y + 22);
  } else {
    tft.setTextColor(COL_TEXT, COL_PANEL);
    tft.drawString("State:", SPRITE_INFO_X + 6, SPRITE_INFO_Y + 6);
    tft.drawString(stateLabel(), SPRITE_INFO_X + 6, SPRITE_INFO_Y + 22);
  }

  lastDrawnScanMode = scanMode;
  lastDrawnEvilTwinState = evilTwinState;
  lastDrawnShowingTwinStatus = showTwinStatus;
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

  for (int i = 0; i < AP_TABLE_SIZE; i++) {
    apTable[i].used = false;
  }
  evilTwinLearningStartMs = millis();
  evilTwinState = TWIN_LEARNING;
  lastTwinClearDisplayMs = evilTwinLearningStartMs;
  showingTwinClearStatus = false;

  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.drawString("Starting Deauth Sluth...", SCREEN_W / 2, SCREEN_H / 2 + 88);
  delay(400);

  initSDCard();

  drawStaticUI();

  lastDrawnState = (ScannerVisualState)255;
  lastDrawnChannel = 255;
  lastDrawnScanMode = (ScanMode)255;
  lastDrawnEvilTwinState = (EvilTwinState)255;
  lastDrawnShowingTwinStatus = false;
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
  processApObservationQueue();
  processSdLogQueue();
  updateGraphIfNeeded();
  hopChannelIfNeeded();
  handleStateTimeout();
  updateLedState();
  copyStatsForUi();
  updateDynamicUI();
  delay(35);
}
