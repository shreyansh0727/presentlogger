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
#define BUZZER_PIN    4  // Signal pin for 3-pin buzzer module
#define GREEN_LED     5
#define RED_LED       3

// Timing
#define HEARTBEAT_MS  30000
#define COOLDOWN_MS   3000
#define MOTION_MS     12000
#define STATUS_UPDATE_MS 10000

// Network
char ssid[] = "YOUR_WIFI_SSID";
char password[] = "YOUR_WIFI_PASSWORD";
char serverAddress[] = "192.168.31.104";
int serverPort = 5000;
char apiKey[] = "your-api-key-here";

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
bool rfidConnected = false;         // NEW: RFID hardware connected?
int dailyScans = 0;
unsigned long lastMotionTime = 0;
unsigned long lastHeartbeat = 0;
unsigned long lastCardTime = 0;
unsigned long lastStatusUpdate = 0;
unsigned long lastRfidCheck = 0;    // NEW: Last RFID health check
String lastCardUID = "";
String serverVer = "";
String deviceId = "";

void setup() {
  Serial.begin(115200);
  Serial1.begin(9600); // UART to UNO Slave
  while (!Serial) delay(10);

  // Initialize pins
  pinMode(PIR_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);

  Serial.println("🚀 Starting Enhanced Arduino UNO R4 WiFi Attendance System v2.0");
  Serial.println("📡 Dual Arduino Setup - Master Controller");

  SPI.begin();
  mfrc522.PCD_Init();
  rfidConnected = mfrc522.PCD_PerformSelfTest(); // NEW: Verify RFID hardware
  if (rfidConnected) {
    Serial.println("✅ MFRC522 RFID Reader initialized & connected");
  } else {
    Serial.println("❌ RFID Reader Self-Test Failed! Check wiring/power.");
  }

  sendStatusUpdates(); // Send initial status to Slave

  initializeRTC();
  connectToWiFi();
  deviceId = getDeviceId();

  Serial.println("🎉 Master Arduino Ready - Waiting for motion...");
}

void loop() {
  // Send periodic status updates to slave
  if (millis() - lastStatusUpdate > STATUS_UPDATE_MS) {
    sendStatusUpdates();
    lastStatusUpdate = millis();
  }

  // Send heartbeat to Flask
  if (wifiConnected && serverConnected && millis() - lastHeartbeat > HEARTBEAT_MS) {
    sendHeartbeat();
    lastHeartbeat = millis();
  }

  // RFID hardware health check (periodic)
  if (millis() - lastRfidCheck > 15000) {
    bool ok = mfrc522.PCD_PerformSelfTest();
    if (ok != rfidConnected) {
      rfidConnected = ok;
      sendStatusUpdates();
      if (!rfidConnected) {
        sendToSlave("SCREEN:ERROR,RFID Error,Check reader connection");
      } else {
        sendToSlave("SCREEN:READY");
      }
    }
    lastRfidCheck = millis();
  }

  // PIR motion detection
  if (digitalRead(PIR_PIN) == HIGH && !pirTriggered) {
    pirTriggered = true;
    systemActive = true;
    lastMotionTime = millis();
    sendToSlave("SCREEN:SCAN_MOTION");
    Serial.println("👋 Motion detected - RFID scanner activated");
  }

  // RFID scanning window (12 seconds after motion)
  if (systemActive && millis() - lastMotionTime < MOTION_MS && rfidConnected) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String rfidUID = getRFIDString();
      if (rfidUID != lastCardUID || millis() - lastCardTime > COOLDOWN_MS) {
        Serial.println("📝 Processing RFID UID: " + rfidUID);
        processAttendance(rfidUID);
        lastCardUID = rfidUID;
        lastCardTime = millis();
        dailyScans++;
      } else {
        Serial.println("⚠️ Duplicate card scan ignored (cooldown active)");
        sendToSlave("SCREEN:DUPLICATE");
        buzzerFail();
        delay(1000);
      }
      mfrc522.PICC_HaltA();
      systemActive = false;
      pirTriggered = false;
    }
  } else if (systemActive) {
    systemActive = false;
    pirTriggered = false;
    sendToSlave("SCREEN:TIMEOUT");
    Serial.println("⏰ Scan timeout - returning to ready state");
    delay(2000);
    sendToSlave("SCREEN:READY");
  }

  // Clear PIR trigger when motion stops
  if (pirTriggered && digitalRead(PIR_PIN) == LOW && millis() - lastMotionTime > 1000) {
    pirTriggered = false;
  }
  
  delay(100);
}

void initializeRTC() {
  if (RTC.begin()) {
    rtcInitialized = true;
    RTCTime startTime(22, Month::SEPTEMBER, 2025, 11, 40, 0, DayOfWeek::MONDAY, SaveLight::SAVING_TIME_ACTIVE);
    RTC.setTime(startTime);
    Serial.println("✅ RTC initialized successfully");
  } else {
    Serial.println("❌ RTC initialization failed");
  }
}

void connectToWiFi() {
  sendToSlave("SCREEN:CONNECTING");
  sendToSlave("STATUS:WIFI:Connecting");
  Serial.println("📶 Connecting to WiFi network...");
  
  if (WiFi.status() == WL_NO_MODULE) {
    wifiConnected = false;
    sendToSlave("STATUS:WIFI:Module Failed");
    sendToSlave("SCREEN:ERROR,WiFi Module,Not found");
    Serial.println("❌ Communication with WiFi module failed");
    return;
  }
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 10) {
    WiFi.begin(ssid, password);
    delay(3000);
    attempts++;
    sendToSlave("STATUS:WIFI:Attempt " + String(attempts));
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    sendToSlave("STATUS:WIFI:Connected");
    Serial.println("✅ WiFi Connected Successfully");
    
    if (rtcInitialized) {
      syncTimeWithNTP();
    }
    
    if (testFlaskConnection()) {
      serverConnected = true;
      sendToSlave("STATUS:SERVER:Online");
      Serial.println("✅ Flask server connection successful");
    } else {
      serverConnected = false;
      sendToSlave("STATUS:SERVER:Offline");
      Serial.println("❌ Flask server connection failed");
    }
    sendToSlave("SCREEN:READY");
  } else {
    wifiConnected = false;
    sendToSlave("STATUS:WIFI:Failed");
    sendToSlave("SCREEN:ERROR,No WiFi,Check connection");
    Serial.println("❌ WiFi connection failed");
  }
}

bool testFlaskConnection() {
  sendToSlave("STATUS:SERVER:Testing");
  client.beginRequest();
  client.get("/");
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  if (statusCode == 200) {
    DynamicJsonDocument doc(512);
    if (!deserializeJson(doc, response) && doc["status"] == "active") {
      serverVer = doc["version"].as<String>();
      return true;
    }
  }
  sendToSlave("STATUS:SERVER:Auth Failed");
  return false;
}

void syncTimeWithNTP() {
  unsigned long epochTime = WiFi.getTime();
  if (epochTime > 0) {
    RTCTime timeToSet = RTCTime(epochTime);
    RTC.setTime(timeToSet);
  }
}

String getDeviceId() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  String macAddressStr = "";
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) macAddressStr += "0";
    macAddressStr += String(mac[i], HEX);
    if (i < 5) macAddressStr += ":";
  }
  macAddressStr.toUpperCase();
  return macAddressStr;
}

void sendStatusUpdates() {
  if (wifiConnected) {
    sendToSlave("STATUS:WIFI:Connected");
  } else {
    sendToSlave("STATUS:WIFI:Disconnected");
  }
  
  if (serverConnected) {
    sendToSlave("STATUS:SERVER:Online");
  } else {
    sendToSlave("STATUS:SERVER:Offline");
  }

  sendToSlave("STATUS:RFID:" + String(rfidConnected ? "Connected" : "Disconnected"));
  sendToSlave("INFO:TIME:" + getCurrentTime());
  sendToSlave("INFO:DATE:" + getCurrentDate());
  sendToSlave("INFO:SCANS:" + String(dailyScans));
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
    sendToSlave("SCREEN:ERROR,No WiFi,Check network settings");
    buzzerFail();
    delay(3000);
    sendToSlave("SCREEN:READY");
    return;
  }
  
  if (!serverConnected) {
    sendToSlave("SCREEN:ERROR,Server Error,API not accessible");
    buzzerFail();
    delay(3000);
    sendToSlave("SCREEN:READY");
    return;
  }

  String studentData = getStudentFromEnhancedFlask(rfidUID);
  if (studentData == "NOT_FOUND") {
    sendToSlave("SCREEN:ERROR,Unknown Card,Register in dashboard");
    logUnknownCardToEnhancedFlask(rfidUID);
    buzzerFail();
    delay(3000);
    sendToSlave("SCREEN:READY");
    return;
  }
  
  if (studentData == "ERROR") {
    sendToSlave("SCREEN:ERROR,Server Error,Try again later");
    buzzerFail();
    delay(3000);
    sendToSlave("SCREEN:READY");
    return;
  }

  DynamicJsonDocument doc(1024);
  if (deserializeJson(doc, studentData)) {
    sendToSlave("SCREEN:ERROR,Data Error,Invalid server response");
    buzzerFail();
    delay(3000);
    sendToSlave("SCREEN:READY");
    return;
  }
  
  String studentName = doc["name"];
  String regNo = doc["reg_no"];
  String className = doc["class"];
  bool isPresent = doc["is_present"];
  String currentTime = getCurrentTime();
  String currentDate = getCurrentDate();
  String action = isPresent ? "EXIT" : "ENTRY";

  String logResponse = logAttendanceToEnhancedFlask(rfidUID, regNo, studentName, className, action, currentTime, currentDate);
  if (logResponse != "ERROR") {
    DynamicJsonDocument resDoc(1024);
    if (!deserializeJson(resDoc, logResponse)) {
      bool isLate = resDoc["is_late"] | false;
      if (isLate) {
        sendToSlave("SCREEN:LATE," + studentName + "," + currentTime);
        buzzerWarning();
      } else {
        sendToSlave("SCREEN:SUCCESS," + studentName + "," + className + "," + regNo + "," + action + "," + currentTime + "," + currentDate);
      }
      buzzerSuccess();
      digitalWrite(GREEN_LED, HIGH);
      delay(3000);
      digitalWrite(GREEN_LED, LOW);
    } else {
      sendToSlave("SCREEN:ERROR,Server Error,Failed to save data");
      buzzerFail();
    }
    delay(3000);
    sendToSlave("SCREEN:READY");
  } else {
    sendToSlave("SCREEN:ERROR,Server Error,Failed to save data");
    buzzerFail();
    delay(3000);
    sendToSlave("SCREEN:READY");
  }
}

String getStudentFromEnhancedFlask(String uid) {
  String endpoint = "/api/student?uid=" + uid;
  client.beginRequest();
  client.get(endpoint);
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
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
  String macAddressStr = "";
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) macAddressStr += "0";
    macAddressStr += String(mac[i], HEX);
    if (i < 5) macAddressStr += ":";
  }
  macAddressStr.toUpperCase();

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
  doc["device_info"]["mac_address"] = macAddressStr;

  String jsonPayload;
  serializeJson(doc, jsonPayload);
  client.beginRequest();
  client.post("/api/attendance/log");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  return (statusCode == 200 ? client.responseBody() : "ERROR");
}

void logUnknownCardToEnhancedFlask(String uid) {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  String macAddressStr = "";
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) macAddressStr += "0";
    macAddressStr += String(mac[i], HEX);
    if (i < 5) macAddressStr += ":";
  }
  macAddressStr.toUpperCase();

  DynamicJsonDocument doc(512);
  doc["rfid_uid"] = uid;
  doc["timestamp"] = getCurrentTime();
  doc["date"] = getCurrentDate();
  doc["device_info"]["type"] = "Arduino UNO R4 WiFi";
  doc["device_info"]["location"] = "Main Entrance";
  doc["device_info"]["mac_address"] = macAddressStr;

  String jsonPayload;
  serializeJson(doc, jsonPayload);
  client.beginRequest();
  client.post("/api/attendance/unknown");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
}

void sendHeartbeat() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  String macAddressStr = "";
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 16) macAddressStr += "0";
    macAddressStr += String(mac[i], HEX);
    if (i < 5) macAddressStr += ":";
  }
  macAddressStr.toUpperCase();

  DynamicJsonDocument doc(512);
  doc["device_type"] = "Arduino UNO R4 WiFi";
  doc["mac_address"] = macAddressStr;
  doc["uptime"] = millis();
  doc["daily_scans"] = dailyScans;
  doc["wifi_rssi"] = WiFi.RSSI();
  doc["timestamp"] = getCurrentTime();

  String jsonPayload;
  serializeJson(doc, jsonPayload);
  client.beginRequest();
  client.post("/api/system/heartbeat");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
}

String getCurrentTime() {
  if (rtcInitialized) {
    RTCTime now;
    RTC.getTime(now);
    char buf[9];
    sprintf(buf, "%02d:%02d:%02d", now.getHour(), now.getMinutes(), now.getSeconds());
    return String(buf);
  }
  unsigned long up = millis();
  unsigned long sec = (up / 1000) % 60;
  unsigned long min = (up / 60000) % 60;
  unsigned long hr = (up / 3600000) % 24;
  char buf[9];
  sprintf(buf, "%02lu:%02lu:%02lu", hr, min, sec);
  return String(buf);
}

String getCurrentDate() {
  if (rtcInitialized) {
    RTCTime now;
    RTC.getTime(now);
    char buf[11];
    sprintf(buf, "%04d-%02d-%02d", now.getYear(), now.getMonth(), now.getDayOfMonth());
    return String(buf);
  }
  return "2025-09-22";
}

void buzzerSuccess() {
  digitalWrite(BUZZER_PIN, HIGH); delay(100);
  digitalWrite(BUZZER_PIN, LOW); delay(50);
  digitalWrite(BUZZER_PIN, HIGH); delay(100);
  digitalWrite(BUZZER_PIN, LOW); delay(50);
  digitalWrite(BUZZER_PIN, HIGH); delay(100);
  digitalWrite(BUZZER_PIN, LOW);
}

void buzzerFail() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(BUZZER_PIN, HIGH); delay(300);
    digitalWrite(BUZZER_PIN, LOW); delay(200);
  }
}

void buzzerWarning() {
  for (int i = 0; i < 5; i++) {
    digitalWrite(BUZZER_PIN, HIGH); delay(150);
    digitalWrite(BUZZER_PIN, LOW); delay(100);
  }
}

void sendToSlave(String message) {
  Serial1.println(message);
  Serial.println("📤 Sent to display: " + message);
}
