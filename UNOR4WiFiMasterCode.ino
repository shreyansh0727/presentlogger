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
#define HEARTBEAT_MS  30000
#define COOLDOWN_MS   3000
#define MOTION_MS     12000

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
int dailyScans = 0;
unsigned long lastMotionTime = 0;
unsigned long lastHeartbeat = 0;
unsigned long lastCardTime = 0;
String lastCardUID = "";
String serverVer = "";
String deviceId = "";

void setup() {
  Serial.begin(115200);
  Serial1.begin(9600); // UART to UNO Slave
  while (!Serial);

  pinMode(PIR_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);

  SPI.begin();
  mfrc522.PCD_Init();

  initializeRTC();
  connectToWiFi();
  deviceId = getDeviceId();

  sendToSlave("SCREEN:WELCOME");
}

void loop() {
  // Heartbeat to Flask
  if (wifiConnected && millis() - lastHeartbeat > HEARTBEAT_MS) {
    sendHeartbeat();
    lastHeartbeat = millis();
  }

  // PIR motion
  if (digitalRead(PIR_PIN) == HIGH && !pirTriggered) {
    pirTriggered = true;
    systemActive = true;
    lastMotionTime = millis();
    sendToSlave("SCREEN:SCAN_MOTION");
  }

  // RFID window
  if (systemActive && millis() - lastMotionTime < MOTION_MS) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String rfidUID = getRFIDString();
      if (rfidUID != lastCardUID || millis() - lastCardTime > COOLDOWN_MS) {
        processAttendance(rfidUID);
        lastCardUID = rfidUID;
        lastCardTime = millis();
        dailyScans++;
      } else {
        sendToSlave("SCREEN:DUPLICATE");
        buzzerFail();
      }
      mfrc522.PICC_HaltA();
      systemActive = false;
      pirTriggered = false;
    }
  } else if (systemActive) {
    // Timeout
    systemActive = false;
    pirTriggered = false;
    sendToSlave("SCREEN:TIMEOUT");
    delay(2000);
    sendToSlave("SCREEN:READY");
  }

  // Clear PIR trigger
  if (pirTriggered && millis() - lastMotionTime > 1000 && digitalRead(PIR_PIN) == LOW) {
    pirTriggered = false;
  }
  delay(100);
}

// --- Hardware & network setup ---
void initializeRTC() {
  if (RTC.begin()) {
    rtcInitialized = true;
    if (wifiConnected) {
      syncTimeWithNTP();
    }
  }
}

void connectToWiFi() {
  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("WiFi module not found!");
    wifiConnected = false;
    return;
  }
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 10) {
    WiFi.begin(ssid, password);
    delay(3000);
    attempts++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    if (rtcInitialized) {
      syncTimeWithNTP();
    }
    if (testFlaskConnection()) {
      serverConnected = true;
    }
    sendToSlave("SCREEN:READY");
  } else {
    wifiConnected = false;
    sendToSlave("SCREEN:ERROR,No WiFi,Check connection");
  }
}

bool testFlaskConnection() {
  client.beginRequest();
  client.get("/");
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  int code = client.responseStatusCode();
  String body = client.responseBody();
  if (code == 200) {
    DynamicJsonDocument doc(256);
    if (!deserializeJson(doc, body)) {
      if (doc["status"] == "active") {
        serverVer = doc["version"].as<String>();
        return true;
      }
    }
  }
  return false;
}

void syncTimeWithNTP() {
  unsigned long epoch = WiFi.getTime();
  if (epoch > 0) {
    RTCTime time(epoch);
    RTC.setTime(time);
  }
}

String getDeviceId() {
  byte mac[6];
  WiFi.macAddress(mac);
  String id;
  for (byte i = 0; i < 6; i++) {
    if (mac[i] < 0x10) id += "0";
    id += String(mac[i], HEX);
  }
  return id;
}

// --- RFID & attendance processing ---
String getRFIDString() {
  String uid;
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
    return;
  }
  if (!serverConnected) {
    sendToSlave("SCREEN:ERROR,Server Error,API not accessible");
    buzzerFail();
    return;
  }

  // Simulated/fetch student info from Flask (replace with your actual HTTP GET)
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

  // Parse student info
  DynamicJsonDocument doc(256);
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
  String action = isPresent ? "EXIT" : "ENTRY";
  String currentTime = getCurrentTime();
  String currentDate = getCurrentDate();

  // Log to server (your HTTP POST logic)
  if (logAttendanceToEnhancedFlask(rfidUID, regNo, studentName, className, action, currentTime, currentDate)) {
    // Parse server response for late/error
    DynamicJsonDocument resDoc(256);
    if (!deserializeJson(resDoc, studentData)) {
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

// --- HTTP & logging ---
String getStudentFromEnhancedFlask(String uid) {
  String endpoint = "/api/student?uid=" + uid;
  client.beginRequest();
  client.get(endpoint);
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  if (statusCode == 200) {
    DynamicJsonDocument doc(256);
    if (!deserializeJson(doc, response) && doc["found"] == true) {
      return response;
    }
    return "NOT_FOUND";
  } else if (statusCode == 401) {
    return "ERROR";
  } else {
    return "ERROR";
  }
}

bool logAttendanceToEnhancedFlask(String uid, String regNo, String name, String className, String action, String timestamp, String date) {
  DynamicJsonDocument doc(512);
  doc["rfid_uid"] = uid;
  doc["reg_no"] = regNo;
  doc["name"] = name;
  doc["class"] = className;
  doc["action"] = action;
  doc["timestamp"] = timestamp;
  doc["date"] = date;
  doc["device_info"]["type"] = "Arduino UNO R4 WiFi";
  doc["device_info"]["location"] = "Main Entrance";
  doc["device_info"]["mac_address"] = WiFi.macAddress();
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
  return (statusCode == 200);
}

void logUnknownCardToEnhancedFlask(String uid) {
  DynamicJsonDocument doc(256);
  doc["rfid_uid"] = uid;
  doc["timestamp"] = getCurrentTime();
  doc["date"] = getCurrentDate();
  doc["device_info"]["type"] = "Arduino UNO R4 WiFi";
  doc["device_info"]["location"] = "Main Entrance";
  doc["device_info"]["mac_address"] = WiFi.macAddress();
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
  DynamicJsonDocument doc(128);
  doc["device_type"] = "Arduino UNO R4 WiFi";
  doc["mac_address"] = WiFi.macAddress();
  doc["uptime"] = millis();
  doc["daily_scans"] = dailyScans;
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

// --- Time helpers ---
String getCurrentTime() {
  if (rtcInitialized) {
    RTCTime now;
    RTC.getTime(now);
    char buf[9];
    sprintf(buf, "%02d:%02d:%02d", now.getHour(), now.getMinutes(), now.getSeconds());
    return String(buf);
  }
  // Fallback to millis (for debug)
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
  return "2025-09-20"; // Fallback
}

// --- Feedback & UART ---
void buzzerSuccess() {
  tone(BUZZER_PIN, 2000, 100);
  delay(50);
  tone(BUZZER_PIN, 3000, 100);
  delay(50);
  tone(BUZZER_PIN, 2000, 100);
}

void buzzerFail() {
  for (int i = 0; i < 3; i++) {
    tone(BUZZER_PIN, 1000, 300);
    delay(200);
  }
}

void buzzerWarning() {
  for (int i = 0; i < 5; i++) {
    tone(BUZZER_PIN, 1500, 150);
    delay(100);
  }
}

void sendToSlave(String message) {
  Serial1.println(message);
}
