/*
 * IoT Student Attendance System - Arduino UNO R4 WiFi + Flask Backend
 * Hardware: Arduino UNO R4 WiFi + RC522 RFID + PIR + TFT Display
 * Backend: Python Flask REST API with Database
 * Updated: September 10, 2025
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
char serverAddress[] = "192.168.1.100"; // Update with your computer's IP address
int serverPort = 5000;                  // Flask server port

WiFiClient wifi;
HttpClient client = HttpClient(wifi, serverAddress, serverPort);

// System variables
bool systemActive = false;
unsigned long lastMotionTime = 0;
unsigned long rfidActiveWindow = 10000; // 10 seconds
bool pirTriggered = false;
bool wifiConnected = false;
bool rtcInitialized = false;
unsigned long lastCardTime = 0;
String lastCardUID = "";

void setup() {
  Serial.begin(115200);
  while (!Serial) { delay(10); }
  
  Serial.println("🚀 Starting Arduino UNO R4 WiFi Attendance System");
  Serial.println("📡 Connecting to Flask Backend API");
  
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
  
  // Test Flask server connection
  if (wifiConnected) {
    testFlaskConnection();
  }
  
  Serial.println("🎉 Arduino UNO R4 WiFi Attendance System Ready!");
  displayReady();
}

void loop() {
  // Check PIR sensor for motion detection
  if (digitalRead(PIR_PIN) == HIGH && !pirTriggered) {
    pirTriggered = true;
    systemActive = true;
    lastMotionTime = millis();
    
    displayScanMessage();
    Serial.println("👋 Motion detected - RFID scanner activated");
  }
  
  // RFID scanning window (10 seconds after motion)
  if (systemActive && (millis() - lastMotionTime < rfidActiveWindow)) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String rfidUID = getRFIDString();
      
      // Prevent duplicate scans (5-second cooldown)
      if (rfidUID != lastCardUID || (millis() - lastCardTime > 5000)) {
        processAttendanceWithFlask(rfidUID);
        lastCardUID = rfidUID;
        lastCardTime = millis();
      } else {
        Serial.println("⚠️ Duplicate card scan ignored (cooldown active)");
      }
      
      mfrc522.PICC_HaltA();
      systemActive = false;
      pirTriggered = false;
    }
  } else if (systemActive) {
    // Timeout - no card detected within 10 seconds
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
    
    // Set current time (September 10, 2025, 7:05 PM IST)
    RTCTime startTime(10, Month::SEPTEMBER, 2025, 19, 5, 0, DayOfWeek::TUESDAY, SaveLight::SAVING_TIME_ACTIVE);
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
  while (WiFi.status() != WL_CONNECTED && attempts < 15) {
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
    Serial.print("🖥️ Flask Server: http://");
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

void testFlaskConnection() {
  if (!wifiConnected) return;
  
  Serial.println("🧪 Testing Flask server connection...");
  
  client.beginRequest();
  client.get("/");  // Test root endpoint
  client.endRequest();
  
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  if (statusCode == 200) {
    Serial.println("✅ Flask server connection successful!");
    
    // Parse JSON response to verify it's our API
    StaticJsonDocument<200> doc;
    DeserializationError error = deserializeJson(doc, response);
    
    if (!error && doc["status"] == "active") {
      Serial.println("✅ Flask Attendance API verified");
      Serial.println("📋 API Name: " + String(doc["name"].as<const char*>()));
      Serial.println("🔢 API Version: " + String(doc["version"].as<const char*>()));
    }
  } else {
    Serial.print("❌ Flask server connection failed. Status code: ");
    Serial.println(statusCode);
    Serial.println("💡 Make sure Flask app is running:");
    Serial.println("   python app.py");
  }
}

void processAttendanceWithFlask(String rfidUID) {
  Serial.println("📝 Processing RFID UID: " + rfidUID);
  
  if (!wifiConnected) {
    displayError("No WiFi Connection");
    buzzerFail();
    Serial.println("❌ Cannot process attendance - no WiFi connection");
    delay(3000);
    displayReady();
    return;
  }
  
  // Step 1: Look up student in Flask database
  String studentData = getStudentFromFlask(rfidUID);
  
  if (studentData == "NOT_FOUND") {
    displayError("Unknown Card");
    buzzerFail();
    logUnknownCardToFlask(rfidUID);
    Serial.println("❌ Unknown card - UID not found in database");
    delay(3000);
    displayReady();
    return;
  }
  
  // Step 2: Parse student information
  StaticJsonDocument<500> doc;
  DeserializationError error = deserializeJson(doc, studentData);
  
  if (error) {
    Serial.println("❌ JSON parsing error: " + String(error.c_str()));
    displayError("Data Error");
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
  
  // Step 3: Log attendance to Flask API
  bool logSuccess = logAttendanceToFlask(rfidUID, regNo, studentName, className, action, currentTime, currentDate);
  
  if (logSuccess) {
    // Success - show confirmation
    if (action == "ENTRY") {
      displaySuccess("Welcome " + studentName, "Entry: " + currentTime);
      Serial.println("✅ Entry logged successfully for " + studentName);
    } else {
      displaySuccess("Goodbye " + studentName, "Exit: " + currentTime);
      Serial.println("✅ Exit logged successfully for " + studentName);
    }
    
    buzzerSuccess();
    digitalWrite(GREEN_LED, HIGH);
    delay(3000);
    digitalWrite(GREEN_LED, LOW);
  } else {
    // Failed to log attendance
    displayError("Server Error");
    buzzerFail();
    Serial.println("❌ Failed to log attendance to Flask server");
    delay(3000);
  }
  
  displayReady();
}

String getStudentFromFlask(String uid) {
  Serial.println("🔍 Looking up student with UID: " + uid);
  
  String endpoint = "/api/student?uid=" + uid;
  
  client.beginRequest();
  client.get(endpoint);
  client.endRequest();
  
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  Serial.println("📡 Student lookup response - Status: " + String(statusCode));
  
  if (statusCode == 200) {
    // Parse response to check if student was found
    StaticJsonDocument<400> doc;
    DeserializationError error = deserializeJson(doc, response);
    
    if (!error && doc["found"] == true) {
      Serial.println("✅ Student found in Flask database");
      return response;
    } else {
      Serial.println("❌ Student not found in Flask database");
      return "NOT_FOUND";
    }
  } else {
    Serial.println("❌ Flask server error during student lookup");
    return "NOT_FOUND";
  }
}

bool logAttendanceToFlask(String uid, String regNo, String name, String className, String action, String timestamp, String date) {
  Serial.println("📤 Logging attendance to Flask API...");
  
  // Prepare JSON payload
  StaticJsonDocument<400> doc;
  doc["rfid_uid"] = uid;
  doc["reg_no"] = regNo;
  doc["name"] = name;
  doc["class"] = className;
  doc["action"] = action;
  doc["timestamp"] = timestamp;
  doc["date"] = date;
  
  String jsonPayload;
  serializeJson(doc, jsonPayload);
  
  Serial.println("📋 JSON Payload:");
  Serial.println(jsonPayload);
  
  // Send POST request to Flask API
  client.beginRequest();
  client.post("/api/attendance/log");  // Updated endpoint path
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  
  // Get response
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  Serial.println("📥 Flask server response:");
  Serial.println("Status Code: " + String(statusCode));
  Serial.println("Response: " + response);
  
  if (statusCode == 200) {
    Serial.println("✅ Attendance successfully logged to Flask database");
    return true;
  } else {
    Serial.println("❌ Failed to log attendance. Check Flask server logs.");
    return false;
  }
}

void logUnknownCardToFlask(String uid) {
  Serial.println("⚠️ Logging unknown card to Flask API: " + uid);
  
  StaticJsonDocument<200> doc;
  doc["rfid_uid"] = uid;
  doc["timestamp"] = getCurrentTime();
  doc["date"] = getCurrentDate();
  
  String jsonPayload;
  serializeJson(doc, jsonPayload);
  
  client.beginRequest();
  client.post("/api/attendance/unknown");  // Updated endpoint path
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("Content-Length", jsonPayload.length());
  client.print(jsonPayload);
  client.endRequest();
  
  int statusCode = client.responseStatusCode();
  Serial.println("⚠️ Unknown card logged - Status: " + String(statusCode));
}

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
    return "2025-09-10"; // Default current date
  }
}

// Display Functions
void displayWelcome() {
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(40, 50);
  tft.println("Attendance");
  tft.setCursor(60, 80);
  tft.println("System");
  tft.setTextSize(1);
  tft.setCursor(30, 130);
  tft.println("Arduino UNO R4 WiFi");
  tft.setCursor(45, 150);
  tft.println("Flask Backend API");
  tft.setCursor(30, 170);
  tft.println("RA4M1 + ESP32-S3 + RTC");
  tft.setCursor(70, 200);
  tft.println("Initializing...");
}

void displayConnecting() {
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextColor(ILI9341_YELLOW);
  tft.setTextSize(2);
  tft.setCursor(30, 90);
  tft.println("Connecting");
  tft.setCursor(50, 120);
  tft.println("to WiFi...");
  tft.setTextSize(1);
  tft.setCursor(40, 160);
  tft.println("ESP32-S3 WiFi Module");
  tft.setCursor(60, 180);
  tft.println("Please wait...");
}

void displayReady() {
  tft.fillScreen(ILI9341_GREEN);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(3);
  tft.setCursor(70, 40);
  tft.println("READY");
  
  // Show current time and date
  tft.setTextSize(2);
  tft.setCursor(50, 80);
  tft.println(getCurrentTime());
  tft.setTextSize(1);
  tft.setCursor(70, 105);
  tft.println(getCurrentDate());
  
  tft.setCursor(40, 130);
  tft.println("Approach the reader");
  tft.setCursor(60, 150);
  tft.println("with your card");
  
  // Status indicators
  tft.setCursor(10, 180);
  if (wifiConnected) {
    tft.setTextColor(ILI9341_WHITE);
    tft.println("WiFi: Connected");
  } else {
    tft.setTextColor(ILI9341_RED);
    tft.println("WiFi: Offline");
  }
  
  tft.setCursor(10, 200);
  tft.setTextColor(ILI9341_WHITE);
  tft.println("Backend: Flask API");
  
  tft.setCursor(10, 220);
  if (rtcInitialized) {
    tft.println("Clock: NTP Synced");
  } else {
    tft.setTextColor(ILI9341_YELLOW);
    tft.println("Clock: Estimated");
  }
}

void displayScanMessage() {
  tft.fillScreen(ILI9341_BLUE);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(50, 70);
  tft.println("Motion");
  tft.setCursor(40, 100);
  tft.println("Detected");
  tft.setTextSize(1);
  tft.setCursor(50, 140);
  tft.println("Please show your");
  tft.setCursor(70, 160);
  tft.println("RFID card now");
  
  // Show countdown
  tft.setCursor(40, 190);
  tft.println("Scanning for 10 seconds");
}

void displaySuccess(String line1, String line2) {
  tft.fillScreen(ILI9341_GREEN);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(20, 30);
  tft.println("SUCCESS");
  
  tft.setTextSize(1);
  tft.setCursor(10, 80);
  tft.println(line1);
  tft.setCursor(10, 100);
  tft.println(line2);
  tft.setCursor(10, 130);
  tft.println("Date: " + getCurrentDate());
  
  // Show sync status
  tft.setCursor(10, 160);
  if (wifiConnected) {
    tft.println("Synced to Flask Database");
  } else {
    tft.println("Stored locally only");
  }
  
  // Success checkmark
  tft.setTextSize(3);
  tft.setCursor(130, 180);
  tft.println("✓");
}

void displayError(String message) {
  tft.fillScreen(ILI9341_RED);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(60, 70);
  tft.println("ERROR");
  
  tft.setTextSize(1);
  tft.setCursor(30, 110);
  tft.println(message);
  
  if (message == "Unknown Card") {
    tft.setCursor(20, 140);
    tft.println("Please register this");
    tft.setCursor(40, 160);
    tft.println("card in the Flask");
    tft.setCursor(50, 180);
    tft.println("admin dashboard");
  } else if (message == "No WiFi Connection") {
    tft.setCursor(30, 140);
    tft.println("Check WiFi settings");
    tft.setCursor(40, 160);
    tft.println("and network status");
  } else {
    tft.setCursor(30, 140);
    tft.println("Check Flask server");
    tft.setCursor(40, 160);
    tft.println("and try again");
  }
  
  digitalWrite(RED_LED, HIGH);
  delay(2000);
  digitalWrite(RED_LED, LOW);
}

void displayTimeout() {
  tft.fillScreen(ILI9341_ORANGE);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(40, 90);
  tft.println("TIMEOUT");
  tft.setTextSize(1);
  tft.setCursor(50, 130);
  tft.println("No card detected");
  tft.setCursor(40, 150);
  tft.println("within 10 seconds");
  tft.setCursor(50, 180);
  tft.println("Returning to ready");
}

// Buzzer Functions
void buzzerSuccess() {
  digitalWrite(BUZZER_PIN, HIGH);
  delay(150);
  digitalWrite(BUZZER_PIN, LOW);
  delay(100);
  digitalWrite(BUZZER_PIN, HIGH);
  delay(150);
  digitalWrite(BUZZER_PIN, LOW);
}

void buzzerFail() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(BUZZER_PIN, HIGH);
    delay(200);
    digitalWrite(BUZZER_PIN, LOW);
    delay(200);
  }
}
