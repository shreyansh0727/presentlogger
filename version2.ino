#include <SPI.h>
#include <MFRC522.h>
#include <WiFiS3.h>
#include <ArduinoHttpClient.h>
#include <ArduinoJson.h>
#include <RTC.h>

// Pins
#define RST_PIN       9
#define SS_PIN        10
#define PIR_PIN       2
#define BUZZER_PIN    4
#define GREEN_LED     5
#define RED_LED       3

// Timing
#define HEARTBEAT_MS      30000
#define COOLDOWN_MS       3000
#define MOTION_MS         12000
#define STATUS_UPDATE_MS  10000

// Network
char ssid[] = "DESKTOP-0QNV737 2010";
char password[] = "6n8B=193";
char serverAddress[] = "192.168.137.1";
int  serverPort = 5000;
char apiKey[] = "kNvRXwm50g2X2ntyS3nydl0skmTWOwlxVZN6ez39xco";

// Instances
WiFiClient wifi;
HttpClient client(wifi, serverAddress, serverPort);
MFRC522 mfrc522(SS_PIN, RST_PIN);

// State
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

// ---------- Serial UI helpers ----------
void uiBanner() {
  Serial.println("=====================================");
  Serial.println("🚀 UNO R4 WiFi Attendance (Serial UI)");
  Serial.println("=====================================");
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
}
void uiReady() {
  Serial.println("\n✅ === SYSTEM READY ===");
  Serial.println("⏰ " + getCurrentTime() + " | 📅 " + getCurrentDate());
  Serial.println("👋 Approach the reader with your card");
  Serial.println("=======================\n");
}
void uiMotion() {
  Serial.println("\n🚶 === MOTION DETECTED ===");
  Serial.println("Please show your RFID card now");
  Serial.println("12 second scan window active");
  Serial.println("==========================\n");
}
void uiDuplicate() {
  Serial.println("\n⚠️  === DUPLICATE SCAN ===");
  Serial.println("Please wait 3 seconds between scans");
  Serial.println("=========================\n");
}
void uiTimeout() {
  Serial.println("\n⏰ === SCAN TIMEOUT ===");
  Serial.println("No card detected within 12 seconds");
  Serial.println("=======================\n");
}
void uiError(const String& title, const String& msg) {
  Serial.println("\n❌ === ERROR ===");
  Serial.println("🚨 " + title);
  Serial.println("💬 " + msg);
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
  Serial.println("=============================\n");
}
void uiLate(const String& name, const String& t) {
  Serial.println("\n🟠 === LATE ARRIVAL ===");
  Serial.println("👤 Student: " + name);
  Serial.println("🕐 Arrival: " + t);
  Serial.println("📅 Date: " + getCurrentDate());
  Serial.println("=======================\n");
}


String getDeviceId() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// ---------- Setup ----------

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

  uiBanner();

  SPI.begin();
  mfrc522.PCD_Init();
  // Safer comm check (self-test fails often on clones):
  byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
  rfidConnected = (v != 0x00 && v != 0xFF);
  Serial.print("🔍 MFRC522 VersionReg: 0x"); Serial.println(v, HEX);
  Serial.println(rfidConnected ? "✅ RFID comm OK" : "❌ RFID comm failed (check 3.3V, SS=10, SCK=13, MOSI=11, MISO=12, RST=9)");

  if (RTC.begin()) {
    rtcInitialized = true;
    RTCTime t(24, Month::SEPTEMBER, 2025, 9, 15, 0, DayOfWeek::WEDNESDAY, SaveLight::SAVING_TIME_ACTIVE);
    RTC.setTime(t);
    Serial.println("✅ RTC initialized");
  } else {
    Serial.println("❌ RTC init failed");
  }

  connectToWiFi();
  deviceId = getDeviceId();
  uiReady();
}

// ---------- Loop ----------
void loop() {
  // Status tick
  if (millis() - lastStatusUpdate > STATUS_UPDATE_MS) {
    uiStatus();
    lastStatusUpdate = millis();
  }

  // Heartbeat tick
  if (wifiConnected && serverConnected && millis() - lastHeartbeat > HEARTBEAT_MS) {
    sendHeartbeat();
    lastHeartbeat = millis();
  }

  // RFID comm check every 15s
  if (millis() - lastRfidCheck > 15000) {
    byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
    bool ok = (v != 0x00 && v != 0xFF);
    if (ok != rfidConnected) {
      rfidConnected = ok;
      Serial.println(rfidConnected ? "✅ RFID reconnected" : "❌ RFID disconnected");
    }
    lastRfidCheck = millis();
  }

  // PIR motion
  if (digitalRead(PIR_PIN) == HIGH && !pirTriggered) {
    pirTriggered = true;
    systemActive = true;
    lastMotionTime = millis();
    uiMotion();
    Serial.println("👋 Motion detected - RFID active");
  }

  // RFID scan window
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

  delay(50);
}

// ---------- Network ----------
void connectToWiFi() {
  uiConnectingWiFi();
  Serial.println("📶 Connecting WiFi...");

  if (WiFi.status() == WL_NO_MODULE) {
    wifiConnected = false;
    uiError("WiFi Module", "Not found");
    Serial.println("❌ WiFi module not found");
    return;
  }

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 12) {
    WiFi.begin(ssid, password);
    Serial.print("🔄 Attempt "); Serial.print(attempts + 1); Serial.println("/12");
    delay(2500);
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.println("✅ WiFi connected");
    Serial.println("📍 IP: " + WiFi.localIP().toString());
    Serial.println("📶 RSSI: " + String(WiFi.RSSI()) + " dBm");
    if (rtcInitialized) syncTimeWithNTP();

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
    Serial.println("❌ WiFi connection failed");
  }
}

bool testFlaskConnection() {
  Serial.println("🧪 Testing Flask connection...");
  client.beginRequest();
  client.get("/");
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  int statusCode = client.responseStatusCode();
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
  unsigned long epochTime = WiFi.getTime();
  if (epochTime > 0) {
    RTCTime t(epochTime);   // construct a named lvalue
    RTC.setTime(t);         // pass by non-const reference
    Serial.println("🕐 NTP synced: " + getCurrentTime() + " " + getCurrentDate());
  } else {
    Serial.println("⚠️ Failed to get NTP time");
  }
}


// ---------- Attendance ----------
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
    delay(1000);
    uiReady();
    return;
  }
  if (!serverConnected) {
    uiError("Server Error", "API not accessible");
    buzzerFail();
    delay(1000);
    uiReady();
    return;
  }

  String studentData = getStudentFromEnhancedFlask(rfidUID);
  if (studentData == "NOT_FOUND") {
    uiError("Unknown Card", "Register in dashboard");
    logUnknownCardToEnhancedFlask(rfidUID);
    buzzerFail();
    delay(1000);
    uiReady();
    return;
  }
  if (studentData == "ERROR") {
    uiError("Server Error", "Try again later");
    buzzerFail();
    delay(1000);
    uiReady();
    return;
  }

  DynamicJsonDocument doc(1024);
  if (deserializeJson(doc, studentData)) {
    uiError("Data Error", "Invalid server response");
    buzzerFail();
    delay(1000);
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
      bool isLate = resDoc["is_late"] | false;
      if (isLate) {
        uiLate(studentName, t);
        buzzerWarning();
      } else {
        uiSuccess(studentName, className, regNo, action, t, d);
        buzzerSuccess();
      }
      digitalWrite(GREEN_LED, HIGH);
      delay(2000);
      digitalWrite(GREEN_LED, LOW);
    } else {
      uiError("Server Error", "Failed to save data");
      buzzerFail();
    }
    delay(750);
    uiReady();
  } else {
    uiError("Server Error", "Failed to save data");
    buzzerFail();
    delay(750);
    uiReady();
  }
}

// ---------- HTTP helpers ----------
String getStudentFromEnhancedFlask(String uid) {
  String endpoint = "/api/student?uid=" + uid;
  client.beginRequest();
  client.get(endpoint);
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();

  Serial.print("📡 Lookup status: "); Serial.println(statusCode);
  if (statusCode == 200) {
    DynamicJsonDocument doc(1024);
    if (!deserializeJson(doc, response) && doc["found"] == true) {
      return response;
    }
    return "NOT_FOUND";
  }
  return "ERROR";
}

String logAttendanceToEnhancedFlask(String uid, String regNo, String name, String className, String action, String timestamp, String date) {
  uint8_t mac[6];
  WiFi.macAddress(mac);
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

  client.beginRequest();
  client.post("/api/attendance/log");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  String body = client.responseBody();

  Serial.print("📥 Log status: "); Serial.println(statusCode);
  Serial.println("📥 Response: " + body);
  return (statusCode == 200 ? body : "ERROR");
}

void logUnknownCardToEnhancedFlask(String uid) {
  uint8_t mac[6];
  WiFi.macAddress(mac);
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
  client.beginRequest();
  client.post("/api/attendance/unknown");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  Serial.print("⚠️ Unknown card log status: "); Serial.println(statusCode);
}

void sendHeartbeat() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
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
}

// ---------- Time helpers ----------
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
    char buf[11]; sprintf(buf, "%04d-%02d-%02d", now.getYear(), now.getMonth(), now.getDayOfMonth());
    return String(buf);
  }
  return "2025-09-24";
}

// ---------- Buzzers ----------
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
