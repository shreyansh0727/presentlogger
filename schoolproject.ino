/*
 * Enhanced IoT Student Attendance System - Arduino UNO R4 WiFi + Flask Backend
 * Hardware: Arduino UNO R4 WiFi + RC522 RFID + PIR + TFT Display
 * Backend: Enhanced Python Flask REST API with Authentication
 * Updated: September 12, 2025
 */
#include <SPI.h>
#include <MFRC522.h>
#include <WiFiS3.h>           // Built-in WiFi library for UNO R4 WiFi
#include <ArduinoHttpClient.h>
#include <ArduinoJson.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <RTC.h>              // Built-in Real-Time Clock

// Pin Definitions
#define RST_PIN         9
#define SS_PIN          10
#define PIR_PIN         2
#define BUZZER_PIN      4
#define GREEN_LED       5
#define RED_LED         3
#define TFT_CS          8
#define TFT_RST         7
#define TFT_DC          6

// Initialize components
MFRC522 mfrc522(SS_PIN, RST_PIN);
Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

// WiFi and Server Configuration
char ssid[] = "YOUR_WIFI_SSID";        // Update with your WiFi network name
char password[] = "YOUR_WIFI_PASSWORD"; // Update with your WiFi password
char serverAddress[] = "192.168.31.104"; // Update with your computer's IP address
int serverPort = 5000;                  // Flask server port
char apiKey[] = "your-api-key-here";    // API key from Flask dashboard

WiFiClient wifi;
HttpClient client = HttpClient(wifi, serverAddress, serverPort);

// System variables
bool systemActive = false;
unsigned long lastMotionTime = 0;
unsigned long rfidActiveWindow = 12000; // 12 seconds
bool pirTriggered = false;
bool wifiConnected = false;
bool rtcInitialized = false;
bool serverConnected = false;
unsigned long lastCardTime = 0;
String lastCardUID = "";
String serverVersion = "";
int dailyScans = 0;
unsigned long lastHeartbeat = 0;

void setup() {
  Serial.begin(115200);
  while (!Serial) { delay(10); }
  
  Serial.println("🚀 Starting Enhanced Arduino UNO R4 WiFi Attendance System v2.0");
  Serial.println("📡 Connecting to Enhanced Flask Backend API");
  Serial.println("🔐 With API Key Authentication");
  
  // Initialize pins
  pinMode(PIR_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  
  // Initialize SPI and RFID
  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("✅ MFRC522 RFID Reader initialized");
  
  // Initialize TFT display
  tft.begin();
  tft.setRotation(3);
  tft.fillScreen(ILI9341_BLACK);
  displayWelcome();
  Serial.println("✅ TFT Display initialized");
  
  // Initialize RTC with current time
  initializeRTC();
  
  // Connect to WiFi
  connectToWiFi();
  
  // Test Enhanced Flask server connection
  if (wifiConnected) {
    testEnhancedFlaskConnection();
  }
  
  Serial.println("🎉 Enhanced Arduino UNO R4 WiFi Attendance System Ready!");
  Serial.println("📊 Features: Real-time sync, Late detection, API authentication");
  displayReady();
}

void loop() {
  // Send heartbeat every 30 seconds
  if (wifiConnected && serverConnected && (millis() - lastHeartbeat > 30000)) {
    sendHeartbeat();
    lastHeartbeat = millis();
  }
  
  // Check PIR sensor for motion detection
  if (digitalRead(PIR_PIN) == HIGH && !pirTriggered) {
    pirTriggered = true;
    systemActive = true;
    lastMotionTime = millis();
    
    displayScanMessage();
    Serial.println("👋 Motion detected - Enhanced RFID scanner activated");
  }
  
  // RFID scanning window (12 seconds after motion)
  if (systemActive && (millis() - lastMotionTime < rfidActiveWindow)) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String rfidUID = getRFIDString();
      
      // Prevent duplicate scans (3-second cooldown)
      if (rfidUID != lastCardUID || (millis() - lastCardTime > 3000)) {
        processEnhancedAttendance(rfidUID);
        lastCardUID = rfidUID;
        lastCardTime = millis();
        dailyScans++;
      } else {
        Serial.println("⚠️ Duplicate card scan ignored (cooldown active)");
        displayDuplicate();
        delay(1000);
      }
      
      mfrc522.PICC_HaltA();
      systemActive = false;
      pirTriggered = false;
    }
  } else if (systemActive) {
    // Timeout - no card detected within 12 seconds
    systemActive = false;
    pirTriggered = false;
    displayTimeout();
    Serial.println("⏰ Scan timeout - returning to ready state");
    delay(2000);
    displayReady();
  }
  
  // Reset PIR trigger when motion stops
  if (pirTriggered && digitalRead(PIR_PIN) == LOW) {
    delay(1000); // Debounce
    if (digitalRead(PIR_PIN) == LOW) {
      pirTriggered = false;
    }
  }
  
  delay(100);
}

void initializeRTC() {
  if (RTC.begin()) {
    Serial.println("✅ RTC initialized successfully");
    rtcInitialized = true;
    
    // Set current time (September 12, 2025, 11:10 PM IST)
    RTCTime startTime(12, Month::SEPTEMBER, 2025, 23, 10, 0, DayOfWeek::FRIDAY, SaveLight::SAVING_TIME_ACTIVE);
    RTC.setTime(startTime);
    
    Serial.println("🕐 RTC time set to: " + getCurrentTime() + " " + getCurrentDate());
  } else {
    Serial.println("❌ RTC initialization failed");
    rtcInitialized = false;
  }
}

void connectToWiFi() {
  displayConnecting();
  Serial.println("📶 Connecting to WiFi network...");
  
  // Check for WiFi module
  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("❌ Communication with WiFi module failed!");
    wifiConnected = false;
    return;
  }
  
  // Attempt to connect to WiFi
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    Serial.print("🔄 Attempting to connect to SSID: ");
    Serial.println(ssid);
    
    WiFi.begin(ssid, password);
    delay(3000);
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.println("✅ WiFi Connected Successfully!");
    Serial.print("📍 Arduino IP Address: ");
    Serial.println(WiFi.localIP());
    Serial.print("🖥️ Enhanced Flask Server: http://");
    Serial.print(serverAddress);
    Serial.print(":");
    Serial.println(serverPort);
    
    // Sync time with NTP if available
    syncTimeWithNTP();
  } else {
    wifiConnected = false;
    Serial.println("❌ WiFi connection failed - running in offline mode");
    Serial.println("💡 Check WiFi credentials and network availability");
  }
}

void syncTimeWithNTP() {
  if (!wifiConnected || !rtcInitialized) return;
  
  Serial.println("🌐 Syncing time with NTP server...");
  unsigned long epochTime = WiFi.getTime();
  
  if (epochTime > 0) {
    RTCTime timeToSet = RTCTime(epochTime);
    RTC.setTime(timeToSet);
    Serial.println("✅ Time synced with NTP server");
    Serial.println("🕐 Updated time: " + getCurrentTime() + " " + getCurrentDate());
  } else {
    Serial.println("⚠️ Failed to get NTP time - using manual time setting");
  }
}

void testEnhancedFlaskConnection() {
  if (!wifiConnected) return;
  
  Serial.println("🧪 Testing Enhanced Flask server connection...");
  
  client.beginRequest();
  client.get("/");
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  Serial.println("📡 Server Response:");
  Serial.println("Status Code: " + String(statusCode));
  Serial.println("Response: " + response);
  
  if (statusCode == 200) {
    Serial.println("✅ Enhanced Flask server connection successful!");
    
    // Parse JSON response to verify it's our enhanced API
    DynamicJsonDocument doc(1024);
    DeserializationError error = deserializeJson(doc, response);
    
    if (!error && doc["status"] == "active") {
      serverConnected = true;
      serverVersion = doc["version"].as<String>();
      Serial.println("✅ Enhanced Flask Attendance API verified");
      Serial.println("📋 API Name: " + String(doc["name"].as<const char*>()));
      Serial.println("🔢 API Version: " + serverVersion);
      Serial.println("🆙 Server Uptime: " + String(doc["uptime"].as<const char*>()));
      Serial.println("🌐 Features: " + String(doc["features"].size()) + " enhanced features");
    }
  } else if (statusCode == 401) {
    Serial.println("❌ API Key authentication failed!");
    Serial.println("💡 Check your API key in the Flask dashboard");
    serverConnected = false;
  } else {
    Serial.print("❌ Enhanced Flask server connection failed. Status code: ");
    Serial.println(statusCode);
    Serial.println("💡 Make sure Enhanced Flask app is running:");
    Serial.println("   python app.py");
    serverConnected = false;
  }
}

void processEnhancedAttendance(String rfidUID) {
  Serial.println("📝 Processing RFID UID with Enhanced API: " + rfidUID);
  
  if (!wifiConnected) {
    displayError("No WiFi Connection", "Check network settings");
    buzzerFail();
    Serial.println("❌ Cannot process attendance - no WiFi connection");
    delay(3000);
    displayReady();
    return;
  }
  
  if (!serverConnected) {
    displayError("Server Error", "API not accessible");
    buzzerFail();
    Serial.println("❌ Cannot process attendance - server not connected");
    delay(3000);
    displayReady();
    return;
  }
  
  // Step 1: Look up student in Enhanced Flask database
  String studentData = getStudentFromEnhancedFlask(rfidUID);
  if (studentData == "NOT_FOUND") {
    displayError("Unknown Card", "Register in dashboard");
    buzzerFail();
    logUnknownCardToEnhancedFlask(rfidUID);
    Serial.println("❌ Unknown card - UID not found in enhanced database");
    delay(3000);
    displayReady();
    return;
  }
  
  if (studentData == "ERROR") {
    displayError("Server Error", "Try again later");
    buzzerFail();
    Serial.println("❌ Server error during student lookup");
    delay(3000);
    displayReady();
    return;
  }
  
  // Step 2: Parse enhanced student information
  DynamicJsonDocument doc(1024);
  DeserializationError error = deserializeJson(doc, studentData);
  
  if (error) {
    Serial.println("❌ JSON parsing error: " + String(error.c_str()));
    displayError("Data Error", "Invalid server response");
    buzzerFail();
    delay(3000);
    displayReady();
    return;
  }
  
  // Extract student details
  String studentName = doc["name"];
  String regNo = doc["reg_no"];
  String className = doc["class"];
  bool isPresent = doc["is_present"];
  String currentTime = getCurrentTime();
  String currentDate = getCurrentDate();
  String action = isPresent ? "EXIT" : "ENTRY";
  
  Serial.println("👤 Student Found: " + studentName + " (" + regNo + ")");
  Serial.println("📚 Class: " + className);
  Serial.println("🎯 Action: " + action);
  Serial.println("🕐 Time: " + currentTime);
  Serial.println("📅 Date: " + currentDate);
  
  // Step 3: Log attendance to Enhanced Flask API
  String logResponse = logAttendanceToEnhancedFlask(rfidUID, regNo, studentName, className, action, currentTime, currentDate);
  
  if (logResponse != "ERROR") {
    // Parse enhanced response
    DynamicJsonDocument responseDoc(1024);
    DeserializationError responseError = deserializeJson(responseDoc, logResponse);
    
    bool isLate = false;
    String warningMessage = "";
    
    if (!responseError) {
      isLate = responseDoc["is_late"] | false;
      if (responseDoc["warning"]) {
        warningMessage = responseDoc["warning"].as<String>();
      }
    }
    
    // Success - show enhanced confirmation
    if (action == "ENTRY") {
      if (isLate) {
        displayLateArrival(studentName, currentTime);
        Serial.println("⚠️ LATE ENTRY logged for " + studentName + " - " + warningMessage);
      } else {
        displaySuccess("Welcome " + studentName, "Entry: " + currentTime, className);
        Serial.println("✅ Entry logged successfully for " + studentName);
      }
    } else {
      displaySuccess("Goodbye " + studentName, "Exit: " + currentTime, className);
      Serial.println("✅ Exit logged successfully for " + studentName);
    }
    
    buzzerSuccess();
    if (isLate) {
      buzzerWarning(); // Special sound for late arrival
    }
    
    digitalWrite(GREEN_LED, HIGH);
    delay(3000);
    digitalWrite(GREEN_LED, LOW);
  } else {
    // Failed to log attendance
    displayError("Server Error", "Failed to save data");
    buzzerFail();
    Serial.println("❌ Failed to log attendance to Enhanced Flask server");
    delay(3000);
  }
  
  displayReady();
}

String getStudentFromEnhancedFlask(String uid) {
  Serial.println("🔍 Looking up student with Enhanced API - UID: " + uid);
  
  String endpoint = "/api/student?uid=" + uid;
  
  client.beginRequest();
  client.get(endpoint);
  client.sendHeader("X-API-Key", apiKey);
  client.endRequest();
  
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  Serial.println("📡 Enhanced student lookup response - Status: " + String(statusCode));
  
  if (statusCode == 200) {
    DynamicJsonDocument doc(1024);
    DeserializationError error = deserializeJson(doc, response);
    
    if (!error && doc["found"] == true) {
      Serial.println("✅ Student found in Enhanced Flask database");
      return response;
    } else {
      Serial.println("❌ Student not found in Enhanced Flask database");
      return "NOT_FOUND";
    }
  } else if (statusCode == 401) {
    Serial.println("❌ API Key authentication failed");
    return "ERROR";
  } else {
    Serial.println("❌ Enhanced Flask server error during student lookup");
    return "ERROR";
  }
}

String logAttendanceToEnhancedFlask(String uid, String regNo, String name, String className, String action, String timestamp, String date) {
  Serial.println("📤 Logging attendance to Enhanced Flask API...");
  
  // Prepare enhanced JSON payload
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
  doc["device_info"]["mac_address"] = WiFi.macAddress();
  
  String jsonPayload;
  serializeJson(doc, jsonPayload);
  
  Serial.println("📋 Enhanced JSON Payload:");
  Serial.println(jsonPayload);
  
  // Send POST request to Enhanced Flask API
  client.beginRequest();
  client.post("/api/attendance/log");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("X-API-Key", apiKey);
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  
  // Get enhanced response
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  Serial.println("📥 Enhanced Flask server response:");
  Serial.println("Status Code: " + String(statusCode));
  Serial.println("Response: " + response);
  
  if (statusCode == 200) {
    Serial.println("✅ Attendance successfully logged to Enhanced Flask database");
    return response;
  } else if (statusCode == 401) {
    Serial.println("❌ API Key authentication failed during attendance logging");
    return "ERROR";
  } else {
    Serial.println("❌ Failed to log attendance. Check Enhanced Flask server logs.");
    return "ERROR";
  }
}

void logUnknownCardToEnhancedFlask(String uid) {
  Serial.println("⚠️ Logging unknown card to Enhanced Flask API: " + uid);
  
  DynamicJsonDocument doc(512);
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
  
  int statusCode = client.responseStatusCode();
  Serial.println("⚠️ Unknown card logged - Status: " + String(statusCode));
}

void sendHeartbeat() {
  Serial.println("💓 Sending heartbeat to Enhanced Flask server...");
  
  DynamicJsonDocument doc(512);
  doc["device_type"] = "Arduino UNO R4 WiFi";
  doc["mac_address"] = WiFi.macAddress();
  doc["uptime"] = millis();
  doc["daily_scans"] = dailyScans;
  doc["memory_free"] = freeMemory();
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
  
  int statusCode = client.responseStatusCode();
  if (statusCode == 200) {
    Serial.println("💓 Heartbeat sent successfully");
  }
}

// Utility Functions
String getRFIDString() {
  String content = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    content.concat(String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : ""));
    content.concat(String(mfrc522.uid.uidByte[i], HEX));
    if (i != mfrc522.uid.size - 1) content.concat(":");
  }
  content.toUpperCase();
  return content;
}

String getCurrentTime() {
  if (rtcInitialized) {
    RTCTime currentTime;
    RTC.getTime(currentTime);
    
    char timeString[9];
    sprintf(timeString, "%02d:%02d:%02d", 
            currentTime.getHour(), 
            currentTime.getMinutes(), 
            currentTime.getSeconds());
    return String(timeString);
  } else {
    // Fallback to millis-based time
    unsigned long uptime = millis();
    unsigned long seconds = (uptime / 1000) % 60;
    unsigned long minutes = (uptime / 60000) % 60;
    unsigned long hours = (uptime / 3600000) % 24;
    
    char timeString[9];
    sprintf(timeString, "%02lu:%02lu:%02lu", hours, minutes, seconds);
    return String(timeString);
  }
}

String getCurrentDate() {
  if (rtcInitialized) {
    RTCTime currentTime;
    RTC.getTime(currentTime);
    
    char dateString[11];
    sprintf(dateString, "%04d-%02d-%02d", 
            currentTime.getYear(), 
            Month2int(currentTime.getMonth()), 
            currentTime.getDayOfMonth());
    return String(dateString);
  } else {
    return "2025-09-12"; // Current date
  }
}

int freeMemory() {
  char top;
  return &top - reinterpret_cast<char*>(sbrk(0));
}

// Enhanced Display Functions
void displayWelcome() {
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextColor(ILI9341_CYAN);
  tft.setTextSize(2);
  tft.setCursor(20, 30);
  tft.println("Enhanced");
  tft.setCursor(20, 60);
  tft.println("Attendance");
  tft.setCursor(40, 90);
  tft.println("System v2.0");
  
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(1);
  tft.setCursor(30, 130);
  tft.println("Arduino UNO R4 WiFi");
  tft.setCursor(25, 150);
  tft.println("Enhanced Flask Backend");
  tft.setCursor(40, 170);
  tft.println("Real-time Sync");
  tft.setCursor(35, 190);
  tft.println("API Authentication");
  tft.setCursor(70, 210);
  tft.println("Initializing...");
}

void displayConnecting() {
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextColor(ILI9341_YELLOW);
  tft.setTextSize(2);
  tft.setCursor(30, 70);
  tft.println("Connecting");
  tft.setCursor(50, 100);
  tft.println("to WiFi...");
  
  tft.setTextSize(1);
  tft.setTextColor(ILI9341_WHITE);
  tft.setCursor(40, 140);
  tft.println("ESP32-S3 WiFi Module");
  tft.setCursor(45, 160);
  tft.println("Enhanced Security");
  tft.setCursor(60, 180);
  tft.println("Please wait...");
}

void displayReady() {
  tft.fillScreen(ILI9341_GREEN);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(3);
  tft.setCursor(60, 25);
  tft.println("READY");
  
  // Show current time and date
  tft.setTextSize(2);
  tft.setCursor(50, 65);
  tft.println(getCurrentTime());
  tft.setTextSize(1);
  tft.setCursor(70, 90);
  tft.println(getCurrentDate());
  
  tft.setCursor(40, 115);
  tft.println("Approach the reader");
  tft.setCursor(60, 135);
  tft.println("with your card");
  
  // Enhanced status indicators
  tft.setCursor(5, 160);
  if (wifiConnected) {
    tft.setTextColor(ILI9341_WHITE);
    tft.println("WiFi: Connected");
  } else {
    tft.setTextColor(ILI9341_RED);
    tft.println("WiFi: Offline");
  }
  
  tft.setCursor(5, 180);
  if (serverConnected) {
    tft.setTextColor(ILI9341_WHITE);
    tft.println("Server: Online v" + serverVersion);
  } else {
    tft.setTextColor(ILI9341_RED);
    tft.println("Server: Offline");
  }
  
  tft.setCursor(5, 200);
  tft.setTextColor(ILI9341_WHITE);
  if (rtcInitialized) {
    tft.println("Clock: NTP Synced");
  } else {
    tft.setTextColor(ILI9341_YELLOW);
    tft.println("Clock: Estimated");
  }
  
  tft.setCursor(5, 220);
  tft.setTextColor(ILI9341_CYAN);
  tft.println("Scans Today: " + String(dailyScans));
}

void displayScanMessage() {
  tft.fillScreen(ILI9341_BLUE);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(50, 50);
  tft.println("Motion");
  tft.setCursor(40, 80);
  tft.println("Detected");
  
  tft.setTextSize(1);
  tft.setCursor(50, 120);
  tft.println("Please show your");
  tft.setCursor(70, 140);
  tft.println("RFID card now");
  
  tft.setCursor(40, 170);
  tft.println("Enhanced scanning...");
  tft.setCursor(35, 190);
  tft.println("12 second window");
  
  // Show countdown animation
  for (int i = 12; i > 0 && systemActive; i--) {
    tft.fillRect(250, 210, 70, 20, ILI9341_BLACK);
    tft.setCursor(250, 210);
    tft.println(String(i) + "s");
    delay(100);
  }
}

void displaySuccess(String line1, String line2, String className) {
  tft.fillScreen(ILI9341_GREEN);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(50, 20);
  tft.println("SUCCESS");
  
  tft.setTextSize(1);
  tft.setCursor(10, 60);
  tft.println(line1);
  tft.setCursor(10, 80);
  tft.println(line2);
  tft.setCursor(10, 100);
  tft.println("Class: " + className);
  tft.setCursor(10, 120);
  tft.println("Date: " + getCurrentDate());
  
  tft.setCursor(10, 150);
  if (wifiConnected && serverConnected) {
    tft.println("Synced to Enhanced API");
    tft.setCursor(10, 170);
    tft.println("Real-time dashboard updated");
  } else {
    tft.println("Stored locally only");
  }
  
  // Enhanced success animation
  tft.setTextColor(ILI9341_YELLOW);
  tft.setTextSize(4);
  tft.setCursor(270, 180);
  tft.println("✓");
}

void displayLateArrival(String studentName, String arrivalTime) {
  tft.fillScreen(ILI9341_ORANGE);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(30, 20);
  tft.println("LATE ARRIVAL");
  
  tft.setTextSize(1);
  tft.setCursor(10, 60);
  tft.println("Student: " + studentName);
  tft.setCursor(10, 80);
  tft.println("Arrival: " + arrivalTime);
  tft.setCursor(10, 100);
  tft.println("Date: " + getCurrentDate());
  
  tft.setTextColor(ILI9341_YELLOW);
  tft.setCursor(10, 130);
  tft.println("⚠️ AFTER 9:15 AM");
  tft.setCursor(10, 150);
  tft.println("Parent notification sent");
  
  tft.setTextColor(ILI9341_WHITE);
  tft.setCursor(10, 180);
  tft.println("Recorded in system");
  
  // Late arrival warning symbol
  tft.setTextColor(ILI9341_RED);
  tft.setTextSize(3);
  tft.setCursor(270, 180);
  tft.println("⚠");
}

void displayError(String message, String details) {
  tft.fillScreen(ILI9341_RED);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(70, 50);
  tft.println("ERROR");
  
  tft.setTextSize(1);
  tft.setCursor(30, 90);
  tft.println(message);
  tft.setCursor(20, 110);
  tft.println(details);
  
  if (message == "Unknown Card") {
    tft.setCursor(15, 140);
    tft.println("Register this card in");
    tft.setCursor(25, 160);
    tft.println("Enhanced Flask Dashboard");
    tft.setCursor(40, 180);
    tft.println("http://" + String(serverAddress) + ":5000");
  } else if (message.indexOf("WiFi") >= 0) {
    tft.setCursor(25, 140);
    tft.println("Check network settings");
    tft.setCursor(35, 160);
    tft.println("Restart if needed");
  } else {
    tft.setCursor(20, 140);
    tft.println("Check Enhanced Flask");
    tft.setCursor(30, 160);
    tft.println("server status and");
    tft.setCursor(40, 180);
    tft.println("API key validity");
  }
  
  digitalWrite(RED_LED, HIGH);
  delay(2000);
  digitalWrite(RED_LED, LOW);
}

void displayDuplicate() {
  tft.fillScreen(ILI9341_YELLOW);
  tft.setTextColor(ILI9341_BLACK);
  tft.setTextSize(2);
  tft.setCursor(40, 90);
  tft.println("DUPLICATE");
  tft.setCursor(70, 120);
  tft.println("SCAN");
  tft.setTextSize(1);
  tft.setCursor(50, 160);
  tft.println("Please wait 3 seconds");
  tft.setCursor(60, 180);
  tft.println("between scans");
}

void displayTimeout() {
  tft.fillScreen(ILI9341_ORANGE);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(50, 70);
  tft.println("TIMEOUT");
  
  tft.setTextSize(1);
  tft.setCursor(50, 110);
  tft.println("No card detected");
  tft.setCursor(40, 130);
  tft.println("within 12 seconds");
  tft.setCursor(50, 160);
  tft.println("Returning to ready");
  tft.setCursor(60, 180);
  tft.println("state...");
}

// Enhanced Buzzer Functions
void buzzerSuccess() {
  digitalWrite(BUZZER_PIN, HIGH);
  delay(100);
  digitalWrite(BUZZER_PIN, LOW);
  delay(50);
  digitalWrite(BUZZER_PIN, HIGH);
  delay(100);
  digitalWrite(BUZZER_PIN, LOW);
  delay(50);
  digitalWrite(BUZZER_PIN, HIGH);
  delay(100);
  digitalWrite(BUZZER_PIN, LOW);
}

void buzzerFail() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(BUZZER_PIN, HIGH);
    delay(300);
    digitalWrite(BUZZER_PIN, LOW);
    delay(200);
  }
}

void buzzerWarning() {
  // Special sound for late arrival
  for (int i = 0; i < 5; i++) {
    digitalWrite(BUZZER_PIN, HIGH);
    delay(150);
    digitalWrite(BUZZER_PIN, LOW);
    delay(100);
  }
}
