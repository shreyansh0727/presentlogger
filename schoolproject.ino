#include <SPI.h>
#include <MFRC522.h>
#include <WiFiS3.h>
#include <ArduinoHttpClient.h>
#include <ArduinoJson.h>
#include <RTC.h>
#include "Arduino_LED_Matrix.h"  // UNO R4 WiFi 12x8 matrix driver

// ---------------------------- Pins ----------------------------
#define RST_PIN       9
#define SS_PIN        10
#define PIR_PIN       2
#define BUZZER_PIN    4
#define GREEN_LED     5
#define RED_LED       3

// --------------------------- Timing ---------------------------
#define HEARTBEAT_MS       30000
#define COOLDOWN_MS        3000
#define MOTION_MS          12000
#define STATUS_UPDATE_MS   10000

// Timezone (IST +5:30)
const long TZ_OFFSET_SECS = 19800;

// -------------------------- Network ---------------------------
char ssid[] = "SHREYANSH 9748";
char password[] = "84!6zA29";
char serverAddress[] = "192.168.137.1";
int  serverPort = 5000;
char apiKey[] = "EUVAP9gi-c2N5giBzpg_CcUQ70UWb4Vf6zk4NMlz9V4";

// ------------------------- Instances --------------------------
WiFiClient wifi;
HttpClient client(wifi, serverAddress, serverPort);
MFRC522 mfrc522(SS_PIN, RST_PIN);
ArduinoLEDMatrix matrix;

// ---------------------- State variables -----------------------
bool systemActive = false;
bool pirTriggered = false;
bool wifiConnected = false;
bool rtcInitialized = false;
bool serverConnected = false;
bool rfidConnected = false;
int dailyScans = 0;

unsigned long lastMotionTime = 0;
unsigned long lastHeartbeat = 0;
unsigned long lastCardTime = 0;
unsigned long lastStatusUpdate = 0;
unsigned long lastRfidCheck = 0;

String lastCardUID = "";
String serverVer = "";
String deviceId = "";

// ======================== Animator (non-blocking) =========================
struct Frame {
  uint32_t w0, w1, w2;
  uint16_t ms;
};

static inline void load3(const Frame& f) {
  uint32_t buf[3] = { f.w0, f.w1, f.w2 };
  matrix.loadFrame(buf);
}

class Animator {
 public:
  void play(const Frame* seq, size_t count, bool loop=true, bool clearAfter=false) {
    sequence = seq; length = count; looping = loop; index = 0; nextAt = 0;
    running = (seq && count); clearOnStop = clearAfter;
  }
  void stop() { running = false; if (clearOnStop) matrix.clear(); }
  bool isRunning() const { return running; }
  void update() {
    if (!running) return;
    const unsigned long now = millis();
    if (now >= nextAt) {
      const Frame& f = sequence[index];
      load3(f);
      nextAt = now + f.ms;
      index++;
      if (index >= length) {
        if (looping) index = 0;
        else { running = false; if (clearOnStop) matrix.clear(); }
      }
    }
  }
 private:
  const Frame* sequence = nullptr;
  size_t length = 0, index = 0;
  bool looping = true, running = false, clearOnStop = false;
  unsigned long nextAt = 0;
};

Animator anim;

// Cooperative waits that keep animations running
static void waitWithAnim(uint32_t ms) {
  const unsigned long t0 = millis();
  while (millis() - t0 < ms) { anim.update(); delay(1); }
}
static void waitAnimDone() {
  while (anim.isRunning()) { anim.update(); delay(1); }
}

// ======================= Frames (12x8 timed) =======================
// 1) Advanced pulsing heartbeat
static const Frame HEART[] = {
  { 0x00000000, 0x00000000, 0x060C0000,  80 },
  { 0x00000000, 0x06CC6000, 0x04489000,  70 },
  { 0x06CC6600, 0x04489910, 0x0264A400,  60 },
  { 0x036DCC9C, 0x0449991C, 0x0264A400, 100 },
  { 0x3FFFFFFF, 0x7FFFFFFF, 0x3FFFFFFF, 150 },
  { 0x036DCC9C, 0x0449991C, 0x0264A400,  80 },
  { 0x06CC6600, 0x04489910, 0x0264A400,  60 },
  { 0x00000000, 0x06CC6000, 0x04489000,  70 },
  { 0x00000000, 0x00000000, 0x060C0000, 100 },
  { 0x00000000, 0x06CC6000, 0x04489000,  60 },
  { 0x036DCC9C, 0x0449991C, 0x0264A400,  80 },
  { 0x3FFFFFFF, 0x7FFFFFFF, 0x3FFFFFFF, 120 },
  { 0x06CC6600, 0x04489910, 0x0264A400,  60 },
  { 0x00000000, 0x00000000, 0x060C0000,  80 }
};

// 2) Wi‑Fi signal waves
static const Frame WIFI[] = {
  { 0x00000000, 0x01800000, 0x00000000, 100 },
  { 0x00000000, 0x03C00000, 0x18000000, 120 },
  { 0x7E000000, 0x42000000, 0x3C000000, 140 },
  { 0xFF800000, 0x80400000, 0x7E000000, 160 },
  { 0xFFC00000, 0x80200000, 0xFF800000, 200 },
};

// 3) Success checkmark
static const Frame CHECK[] = {
  { 0x00000000, 0x00000000, 0x00100000, 100 },
  { 0x00000000, 0x00000000, 0x00180000,  80 },
  { 0x00000000, 0x00100000, 0x001C0000,  80 },
  { 0x00200000, 0x00180000, 0x001E0000,  80 },
  { 0x00600000, 0x001C0000, 0x001F0000,  80 },
  { 0x00E00000, 0x001E0000, 0x001F8000, 200 },
  { 0x00FE0000, 0x001FE000, 0x001FF800, 300 },
  { 0x00E00000, 0x001E0000, 0x001F8000, 150 },
};

// 4) Error X
static const Frame ERRORX[] = {
  { 0x81000000, 0x42000000, 0x81000000, 100 },
  { 0xC3000000, 0x66000000, 0xC3000000,  80 },
  { 0xE7000000, 0x7E000000, 0xE7000000,  60 },
  { 0xFF800000, 0xFF800000, 0xFF800000, 150 },
  { 0xE7000000, 0x7E000000, 0xE7000000,  60 },
  { 0xC3000000, 0x66000000, 0xC3000000,  80 },
  { 0x81000000, 0x42000000, 0x81000000, 100 },
};

// 5) Loading spinner (looping)
static const Frame SPINNER[] = {
  { 0x18000000, 0x00000000, 0x00000000, 80 },
  { 0x30000000, 0x00000000, 0x00000000, 80 },
  { 0x00000000, 0x30000000, 0x00000000, 80 },
  { 0x00000000, 0x00000000, 0x18000000, 80 },
  { 0x00000000, 0x00000000, 0x0C000000, 80 },
  { 0x00000000, 0x00000000, 0x06000000, 80 },
  { 0x00000000, 0x06000000, 0x00000000, 80 },
  { 0x0C000000, 0x00000000, 0x00000000, 80 },
};

// 6) RFID scan waves
static const Frame SCAN[] = {
  { 0x00000000, 0x01800000, 0x00000000, 100 },
  { 0x00000000, 0x03C00000, 0x24000000, 120 },
  { 0x7E000000, 0x66000000, 0x7E000000, 140 },
  { 0xFF800000, 0xC1800000, 0xFF800000, 160 },
  { 0xFFC00000, 0x80400000, 0xFFC00000, 200 },
};

// 7) Boot sequence
static const Frame BOOT[] = {
  { 0x80000000, 0x00000000, 0x00000000, 100 },
  { 0xC0000000, 0x00000000, 0x00000000,  80 },
  { 0xF0000000, 0x00000000, 0x00000000,  80 },
  { 0xFF000000, 0x00000000, 0x00000000, 120 },
  { 0xFF000000, 0x80000000, 0x00000000,  80 },
  { 0xFF000000, 0xFF000000, 0x00000000, 120 },
  { 0xFF000000, 0xFF000000, 0x80000000,  80 },
  { 0xFF000000, 0xFF000000, 0xFF000000, 300 },
};

// 8) Text glyphs (single-frame)
static const Frame TEXT_R[]   = { { 0xFC000000, 0x84840000, 0x78840000, 300 } };
static const Frame TEXT_E[]   = { { 0xFC000000, 0x80840000, 0xFC000000, 300 } };
static const Frame TEXT_A[]   = { { 0x78000000, 0x84FC0000, 0x84000000, 300 } };
static const Frame TEXT_D[]   = { { 0xF8000000, 0x84840000, 0xF8000000, 300 } };
static const Frame TEXT_Y[]   = { { 0x84000000, 0x48300000, 0x30000000, 300 } };
static const Frame TEXT_OK[]  = { { 0x78840000, 0x84788400, 0x78000000, 500 } };
static const Frame TEXT_ERR[] = { { 0xFC808400, 0xF8FC8000, 0xFC000000, 500 } };

// ===================== Forward declarations (safe) =======================
void uiBanner();
void uiStatus();
void uiConnectingWiFi();
void uiReady();
void uiMotion();
void uiError(const String& title, const String& msg);
void uiSuccess(const String& name, const String& className, const String& regNo, const String& action, const String& t, const String& d);
void uiDuplicate();
void uiTimeout();
void uiLate(const String& name, const String& t);  // ensures visibility

String getCurrentTime();
String getCurrentDate();
String getRFIDString();
void connectToWiFi();
bool testFlaskConnection();
void syncTimeWithNTP();
void sendHeartbeat();
void processAttendance(String rfidUID);
String getStudentFromEnhancedFlask(String uid);
String logAttendanceToEnhancedFlask(String uid, String regNo, String name, String className, String action, String timestamp, String date);
void logUnknownCardToEnhancedFlask(String uid);
void buzzerSuccess();
void buzzerFail();
void buzzerWarning();

// ======================= UI animation wrappers ============================
static void showAdvancedHeartbeat() {
  Serial.println("💓 Advanced heartbeat animation");
  anim.play(HEART, sizeof(HEART)/sizeof(HEART[0]), false, true);
  waitAnimDone();
}
static void showWiFiWaves() {
  Serial.println("📶 WiFi connection waves");
  for (int i=0; i<3; i++) { anim.play(WIFI, sizeof(WIFI)/sizeof(WIFI[0]), false, true); waitAnimDone(); }
}
static void startLoadingSpinner() {
  Serial.println("⏳ Loading spinner (looping)");
  anim.play(SPINNER, sizeof(SPINNER)/sizeof(SPINNER[0]), true, false);
}
static void stopSpinnerClear() { anim.stop(); matrix.clear(); }
static void showSuccessCheckmark() {
  Serial.println("✅ Success checkmark animation");
  anim.play(CHECK, sizeof(CHECK)/sizeof(CHECK[0]), false, true); waitAnimDone();
}
static void showErrorFlash() {
  Serial.println("❌ Error flash animation");
  for (int i=0; i<3; i++) { anim.play(ERRORX, sizeof(ERRORX)/sizeof(ERRORX[0]), false, true); waitAnimDone(); }
}
static void showRFIDScanWaves() {
  Serial.println("📡 RFID scan waves");
  for (int i=0; i<2; i++) { anim.play(SCAN, sizeof(SCAN)/sizeof(SCAN[0]), false, true); waitAnimDone(); }
}
static void showBootSequence() {
  Serial.println("🚀 Boot sequence animation");
  anim.play(BOOT, sizeof(BOOT)/sizeof(BOOT[0]), false, true); waitAnimDone();
}
static void showScrollingText(String text) {
  Serial.println("📝 Text: " + text);
  if (text.indexOf("READY") >= 0) {
    anim.play(TEXT_R,1,false,true); waitAnimDone();
    anim.play(TEXT_E,1,false,true); waitAnimDone();
    anim.play(TEXT_A,1,false,true); waitAnimDone();
    anim.play(TEXT_D,1,false,true); waitAnimDone();
    anim.play(TEXT_Y,1,false,true); waitAnimDone();
  } else if (text.indexOf("OK") >= 0) {
    anim.play(TEXT_OK,1,false,true); waitAnimDone();
  } else if (text.indexOf("ERR") >= 0) {
    anim.play(TEXT_ERR,1,false,true); waitAnimDone();
  } else {
    anim.play(TEXT_OK,1,false,true); waitAnimDone();
  }
}

// =========================== UI functions ================================
void uiBanner() {
  Serial.println("=====================================");
  Serial.println("🚀 UNO R4 WiFi Attendance (Advanced Matrix)");
  Serial.println("=====================================");
  showBootSequence();
}
void uiStatus() {
  Serial.println("\n📊 === SYSTEM STATUS ===");
  Serial.println("🕐 Time: " + getCurrentTime() + " | Date: " + getCurrentDate());
  Serial.println("📶 WiFi: " + String(wifiConnected ? "Connected" : "Disconnected"));
  Serial.println("🖥️  Server: " + String(serverConnected ? "Online" : "Offline"));
  Serial.println("📡 RFID: " + String(rfidConnected ? "Connected" : "Disconnected"));
  Serial.println("📈 Daily Scans: " + String(dailyScans));
  Serial.println("💾 Uptime: " + String(millis() / 1000) + " s");
  if (wifiConnected) {
    Serial.println("📶 RSSI: " + String(WiFi.RSSI()) + " dBm");
    Serial.println("🌐 IP: " + WiFi.localIP().toString());
  }
  Serial.println("========================\n");
}
void uiConnectingWiFi() {
  Serial.println("\n🔗 === CONNECTING TO WIFI ===");
  Serial.println("Network: " + String(ssid));
  Serial.println("=============================\n");
  showWiFiWaves();
}
void uiReady() {
  Serial.println("\n✅ === SYSTEM READY ===");
  Serial.println("⏰ " + getCurrentTime() + " | 📅 " + getCurrentDate());
  Serial.println("👋 Approach the reader with your card");
  Serial.println("=======================\n");
  showScrollingText("READY");
}
void uiMotion() {
  Serial.println("\n🚶 === MOTION DETECTED ===");
  Serial.println("Please show your RFID card now");
  Serial.println("12 second scan window active");
  Serial.println("==========================\n");
  showRFIDScanWaves();
}
void uiError(const String& title, const String& msg) {
  Serial.println("\n❌ === ERROR ===");
  Serial.println("🚨 " + title);
  Serial.println("💬 " + msg);
  Serial.println("RED LED ON");
  digitalWrite(RED_LED, HIGH);
  showErrorFlash();
  Serial.println("================\n");
}
void uiSuccess(const String& name, const String& className, const String& regNo, const String& action, const String& t, const String& d) {
  Serial.println("\n✅ === ATTENDANCE SUCCESS ===");
  Serial.println("👤 Name: " + name);
  Serial.println("🎓 Class: " + className);
  Serial.println("🆔 Reg No: " + regNo);
  Serial.println("📝 Action: " + action);
  Serial.println("🕐 Time: " + t);
  Serial.println("📅 Date: " + d);
  digitalWrite(RED_LED, LOW);
  showSuccessCheckmark();
  showScrollingText("OK");
  Serial.println("=============================\n");
}
void uiDuplicate() {
  Serial.println("\n⚠️  === DUPLICATE SCAN ===");
  Serial.println("Please wait 3 seconds between scans");
  Serial.println("=========================\n");
  showScrollingText("WAIT");
}
void uiTimeout() {
  Serial.println("\n⏰ === SCAN TIMEOUT ===");
  Serial.println("No card detected within 12 seconds");
  Serial.println("=======================\n");
  showScrollingText("TIMEOUT");
}
void uiLate(const String& name, const String& t) {
  Serial.println("\n🟠 === LATE ARRIVAL ===");
  Serial.println("👤 Student: " + name);
  Serial.println("🕐 Arrival: " + t);
  Serial.println("📅 Date: " + getCurrentDate());
  Serial.println("=======================\n");
  showScrollingText("LATE");
}

// ======================== System helpers and logic ========================
String getDeviceId() {
  uint8_t mac[6]; WiFi.macAddress(mac);
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
  return String(buf);
}

void setup() {
  Serial.begin(115200);
  while (!Serial) { delay(10); }

  pinMode(PIR_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);

  matrix.begin();  // start 12x8 matrix
  uiBanner();

  SPI.begin();
  mfrc522.PCD_Init();
  byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
  rfidConnected = (v != 0x00 && v != 0xFF);
  Serial.print("🔍 MFRC522 VersionReg: 0x"); Serial.println(v, HEX);
  Serial.println(rfidConnected ? "✅ RFID comm OK" : "❌ RFID comm failed");

  if (RTC.begin()) {
    rtcInitialized = true;
    RTCTime t(26, Month::SEPTEMBER, 2025, 19, 11, 0, DayOfWeek::FRIDAY, SaveLight::SAVING_TIME_ACTIVE);
    RTC.setTime(t);
    Serial.println("✅ RTC initialized");
  } else {
    Serial.println("❌ RTC init failed");
  }

  connectToWiFi();
  deviceId = getDeviceId();
  uiReady();
}

void loop() {
  // Always advance animations
  anim.update();

  if (millis() - lastStatusUpdate > STATUS_UPDATE_MS) {
    uiStatus();
    lastStatusUpdate = millis();
  }

  if (wifiConnected && serverConnected && millis() - lastHeartbeat > HEARTBEAT_MS) {
    sendHeartbeat();
    lastHeartbeat = millis();
  }

  if (millis() - lastRfidCheck > 15000) {
    byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
    bool ok = (v != 0x00 && v != 0xFF);
    if (ok != rfidConnected) {
      rfidConnected = ok;
      Serial.println(rfidConnected ? "✅ RFID reconnected" : "❌ RFID disconnected");
    }
    lastRfidCheck = millis();
  }

  if (digitalRead(PIR_PIN) == HIGH && !pirTriggered) {
    pirTriggered = true; systemActive = true; lastMotionTime = millis();
    uiMotion();
    Serial.println("👋 Motion detected - RFID active");
  }

  if (systemActive && (millis() - lastMotionTime) < MOTION_MS && rfidConnected) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String uid = getRFIDString();
      if (uid != lastCardUID || millis() - lastCardTime > COOLDOWN_MS) {
        Serial.println("📝 UID: " + uid);
        processAttendance(uid);
        lastCardUID = uid;
        lastCardTime = millis();
        dailyScans++;
      } else {
        uiDuplicate();
        buzzerFail();
      }
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      systemActive = false;
      pirTriggered = false;
    }
  } else if (systemActive && (millis() - lastMotionTime) >= MOTION_MS) {
    systemActive = false;
    pirTriggered = false;
    uiTimeout();
    Serial.println("⏰ Scan timeout -> ready");
    delay(750);
    uiReady();
  }

  if (pirTriggered && digitalRead(PIR_PIN) == LOW && (millis() - lastMotionTime) > 1000) {
    pirTriggered = false;
  }

  delay(10); // short idle; animations remain smooth
}

void connectToWiFi() {
  uiConnectingWiFi();
  Serial.println("📶 Connecting WiFi...");

  if (WiFi.status() == WL_NO_MODULE) {
    wifiConnected = false;
    uiError("WiFi Module", "Not found");
    return;
  }

  // Looping spinner during attempts
  startLoadingSpinner();
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 12) {
    WiFi.begin(ssid, password);
    Serial.print("🔄 Attempt "); Serial.print(attempts + 1); Serial.println("/12");
    waitWithAnim(1500);
    attempts++;
  }
  stopSpinnerClear();

  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    digitalWrite(RED_LED, LOW);
    matrix.clear();
    Serial.println("✅ WiFi connected");
    Serial.println("📍 IP: " + WiFi.localIP().toString());
    Serial.println("📶 RSSI: " + String(WiFi.RSSI()) + " dBm");

    if (rtcInitialized) syncTimeWithNTP();
    delay(200);

    if (testFlaskConnection()) {
      serverConnected = true;
      Serial.println("✅ Flask server online");
    } else {
      serverConnected = false;
      Serial.println("❌ Flask server offline");
    }
  } else {
    wifiConnected = false;
    uiError("WiFi", "Connection failed");
  }
}

bool testFlaskConnection() {
  Serial.println("🧪 Testing Flask connection...");
  int retries = 0;
  int statusCode = -1;

  while (retries < 3 && statusCode < 0) {
    client.beginRequest();
    client.get("/");
    client.sendHeader("X-API-Key", apiKey);
    client.endRequest();
    statusCode = client.responseStatusCode();

    if (statusCode == -4) {
      Serial.println("⚠️ Connection lost, retrying... (" + String(retries + 1) + "/3)");
      waitWithAnim(500);
      retries++;
    } else if (statusCode < 0) {
      Serial.println("⚠️ HTTP error " + String(statusCode) + ", retrying... (" + String(retries + 1) + "/3)");
      waitWithAnim(500);
      retries++;
    }
  }

  String response = client.responseBody();
  Serial.print("📥 Status: "); Serial.println(statusCode);
  if (statusCode == 200) {
    DynamicJsonDocument doc(512);
    DeserializationError err = deserializeJson(doc, response);
    if (!err && doc["status"] == "active") {
      serverVer = doc["version"].as<String>();
      Serial.println("✅ API active, version: " + serverVer);
      return true;
    } else {
      Serial.println("⚠️ Unexpected home response, but server reachable");
      return true;
    }
  }
  Serial.println("❌ Server not reachable or unauthorized");
  return false;
}

void syncTimeWithNTP() {
  unsigned long epoch = WiFi.getTime();
  if (epoch > 0) {
    epoch += TZ_OFFSET_SECS;
    RTCTime t(epoch);
    RTC.setTime(t);
    Serial.println("🕐 NTP synced: " + getCurrentTime() + " " + getCurrentDate());
  } else {
    Serial.println("⚠️ Failed to get NTP time");
  }
}

void sendHeartbeat() {
  uint8_t mac[6]; WiFi.macAddress(mac);
  String macStr = "";
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) macStr += "0";
    macStr += String(mac[i], HEX);
    if (i < 5) macStr += ":";
  }
  macStr.toUpperCase();

  DynamicJsonDocument doc(512);
  doc["device_type"] = "Arduino UNO R4 WiFi";
  doc["mac_address"] = macStr;
  doc["uptime"] = millis();
  doc["daily_scans"] = dailyScans;
  doc["wifi_rssi"] = WiFi.RSSI();
  doc["timestamp"] = getCurrentTime();

  String jsonPayload; serializeJson(doc, jsonPayload);
  client.beginRequest();
  client.post("/api/system/heartbeat");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  Serial.print("💓 Heartbeat status: "); Serial.println(statusCode);

  if (statusCode == 200) {
    showAdvancedHeartbeat();
  }
}

String getRFIDString() {
  String uid = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(mfrc522.uid.uidByte[i], HEX);
    if (i < mfrc522.uid.size - 1) uid += ":";
  }
  uid.toUpperCase();
  return uid;
}

void processAttendance(String rfidUID) {
  if (!wifiConnected) {
    uiError("No WiFi", "Check network");
    buzzerFail();
    waitWithAnim(1000);
    digitalWrite(RED_LED, LOW);
    uiReady();
    return;
  }
  if (!serverConnected) {
    uiError("Server Error", "API not accessible");
    buzzerFail();
    waitWithAnim(1000);
    digitalWrite(RED_LED, LOW);
    uiReady();
    return;
  }

  String studentData = getStudentFromEnhancedFlask(rfidUID);
  if (studentData == "NOT_FOUND") {
    uiError("Unknown Card", "Register in dashboard");
    Serial.println("⚡ Preparing to log unknown card: " + rfidUID);
    logUnknownCardToEnhancedFlask(rfidUID);
    buzzerFail();
    waitWithAnim(1000);
    digitalWrite(RED_LED, LOW);
    uiReady();
    return;
  }
  if (studentData == "ERROR") {
    uiError("Server Error", "Try again later");
    buzzerFail();
    waitWithAnim(1000);
    digitalWrite(RED_LED, LOW);
    uiReady();
    return;
  }

  DynamicJsonDocument doc(1024);
  if (deserializeJson(doc, studentData)) {
    uiError("Data Error", "Invalid server response");
    buzzerFail();
    waitWithAnim(1000);
    digitalWrite(RED_LED, LOW);
    uiReady();
    return;
  }

  String studentName = doc["name"];
  String regNo = doc["reg_no"];
  String className = doc["class"];
  bool isPresent = doc["is_present"];
  String t = getCurrentTime();
  String d = getCurrentDate();
  String action = isPresent ? "EXIT" : "ENTRY";

  String logResponse = logAttendanceToEnhancedFlask(rfidUID, regNo, studentName, className, action, t, d);
  if (logResponse != "ERROR") {
    DynamicJsonDocument resDoc(1024);
    if (!deserializeJson(resDoc, logResponse)) {
      bool late = resDoc["is_late"] | false;
      if (late) {
        uiLate(studentName, t);
        buzzerWarning();
      } else {
        uiSuccess(studentName, className, regNo, action, t, d);
        buzzerSuccess();
      }
      digitalWrite(GREEN_LED, HIGH);
      waitWithAnim(2000);
      digitalWrite(GREEN_LED, LOW);
    } else {
      uiError("Server Error", "Failed to save data");
      buzzerFail();
    }
    waitWithAnim(750);
    digitalWrite(RED_LED, LOW);
    uiReady();
  } else {
    uiError("Server Error", "Failed to save data");
    buzzerFail();
    waitWithAnim(750);
    digitalWrite(RED_LED, LOW);
    uiReady();
  }
}

String getStudentFromEnhancedFlask(String uid) {
  String endpoint = "/api/student?uid=" + uid;

  int retries = 0;
  int statusCode = -1;
  String response = "";

  while (retries < 2 && statusCode < 0) {
    client.beginRequest();
    client.get(endpoint);
    client.sendHeader("X-API-Key", apiKey);
    client.endRequest();
    statusCode = client.responseStatusCode();
    response = client.responseBody();

    if (statusCode == -4) {
      Serial.println("⚠️ Student lookup connection lost, retrying... (" + String(retries + 1) + "/2)");
      waitWithAnim(500);
      retries++;
    } else if (statusCode < 0) {
      Serial.println("⚠️ Student lookup HTTP error " + String(statusCode) + ", retrying... (" + String(retries + 1) + "/2)");
      waitWithAnim(500);
      retries++;
    }
  }

  Serial.print("📡 Lookup status: "); Serial.println(statusCode);
  if (statusCode == 200) {
    DynamicJsonDocument doc(1024);
    if (!deserializeJson(doc, response) && doc["found"] == true) {
      return response;
    }
    return "NOT_FOUND";
  }
  if (statusCode == 404 || statusCode == 204) {
    Serial.println("ℹ️ Student not found (HTTP " + String(statusCode) + ")");
    return "NOT_FOUND";
  }
  Serial.println("❌ Lookup error (HTTP " + String(statusCode) + ")");
  return "ERROR";
}

String logAttendanceToEnhancedFlask(String uid, String regNo, String name, String className, String action, String timestamp, String date) {
  uint8_t mac[6]; WiFi.macAddress(mac);
  String macStr = "";
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) macStr += "0";
    macStr += String(mac[i], HEX);
    if (i < 5) macStr += ":";
  }
  macStr.toUpperCase();

  DynamicJsonDocument doc(1024);
  doc["rfid_uid"] = uid;
  doc["reg_no"] = regNo;
  doc["name"] = name;
  doc["class"] = className;
  doc["action"] = action;
  doc["timestamp"] = timestamp;
  doc["date"] = date;
  doc["device_info"]["type"] = "Arduino UNO R4 WiFi";
  doc["device_info"]["location"] = "Main Entrance";
  doc["device_info"]["mac_address"] = macStr;

  String jsonPayload; serializeJson(doc, jsonPayload);
  Serial.println("📤 Log payload: " + jsonPayload);

  int retries = 0;
  int statusCode = -1;
  String body = "";

  while (retries < 2 && statusCode < 0) {
    client.beginRequest();
    client.post("/api/attendance/log");
    client.sendHeader("Content-Type", "application/json");
    client.sendHeader("X-API-Key", apiKey);
    client.sendHeader("Content-Length", jsonPayload.length());
    client.print(jsonPayload);
    client.endRequest();
    statusCode = client.responseStatusCode();
    body = client.responseBody();

    if (statusCode == -4) {
      Serial.println("⚠️ Attendance log connection lost, retrying... (" + String(retries + 1) + "/2)");
      waitWithAnim(500);
      retries++;
    } else if (statusCode < 0) {
      Serial.println("⚠️ Attendance log HTTP error " + String(statusCode) + ", retrying... (" + String(retries + 1) + "/2)");
      waitWithAnim(500);
      retries++;
    }
  }

  Serial.print("📥 Log status: "); Serial.println(statusCode);
  Serial.println("📥 Response: " + body);
  return (statusCode == 200 ? body : "ERROR");
}

void logUnknownCardToEnhancedFlask(String uid) {
  uint8_t mac[6]; WiFi.macAddress(mac);
  String macStr = "";
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) macStr += "0";
    macStr += String(mac[i], HEX);
    if (i < 5) macStr += ":";
  }
  macStr.toUpperCase();

  DynamicJsonDocument doc(512);
  doc["rfid_uid"] = uid;
  doc["timestamp"] = getCurrentTime();
  doc["date"] = getCurrentDate();
  doc["device_info"]["type"] = "Arduino UNO R4 WiFi";
  doc["device_info"]["location"] = "Main Entrance";
  doc["device_info"]["mac_address"] = macStr;

  String jsonPayload; serializeJson(doc, jsonPayload);
  Serial.println("📤 Unknown payload: " + jsonPayload);

  client.beginRequest();
  client.post("/api/attendance/unknown");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  String body = client.responseBody();
  Serial.print("⚠️ Unknown card log status: "); Serial.println(statusCode);
  Serial.println("⚠️ Response: " + body);

  if (statusCode != 200) {
    waitWithAnim(300);
    client.beginRequest();
    client.post("/api/attendance/unknown");
    client.sendHeader("Content-Type", "application/json");
    client.sendHeader("X-API-Key", apiKey);
    client.sendHeader("Content-Length", jsonPayload.length());
    client.print(jsonPayload);
    client.endRequest();
    int statusCode2 = client.responseStatusCode();
    String body2 = client.responseBody();
    Serial.print("⚠️ Unknown card retry status: "); Serial.println(statusCode2);
    Serial.println("⚠️ Retry response: " + body2);
  }
}

String getCurrentTime() {
  if (rtcInitialized) {
    RTCTime now; RTC.getTime(now);
    char buf[9]; sprintf(buf, "%02d:%02d:%02d", now.getHour(), now.getMinutes(), now.getSeconds());
    return String(buf);
  }
  unsigned long up = millis();
  char buf[9]; sprintf(buf, "%02lu:%02lu:%02lu", (up/3600000)%24, (up/60000)%60, (up/1000)%60);
  return String(buf);
}

String getCurrentDate() {
  if (rtcInitialized) {
    RTCTime now; RTC.getTime(now);
    int y = now.getYear();
    int m = static_cast<int>(now.getMonth());
    int d = now.getDayOfMonth();
    if (m < 1) m = 1;
    if (m > 12) m = 12;
    char buf[11]; sprintf(buf, "%04d-%02d-%02d", y, m+1, d);
    return String(buf);
  }
  return "2025-09-26";
}

// Buzzer helpers (can be converted to non-blocking if desired)
void buzzerSuccess() {
  digitalWrite(BUZZER_PIN, HIGH); delay(100);
  digitalWrite(BUZZER_PIN, LOW);  delay(50);
  digitalWrite(BUZZER_PIN, HIGH); delay(100);
  digitalWrite(BUZZER_PIN, LOW);  delay(50);
  digitalWrite(BUZZER_PIN, HIGH); delay(100);
  digitalWrite(BUZZER_PIN, LOW);
}
void buzzerFail() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(BUZZER_PIN, HIGH); delay(300);
    digitalWrite(BUZZER_PIN, LOW);  delay(200);
  }
}
void buzzerWarning() {
  for (int i = 0; i < 5; i++) {
    digitalWrite(BUZZER_PIN, HIGH); delay(150);
    digitalWrite(BUZZER_PIN, LOW);  delay(100);
  }
}
