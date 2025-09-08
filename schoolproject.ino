/*
 * IoT Student Attendance System - Arduino UNO R4 WiFi
 * Hardware: Arduino UNO R4 WiFi + RC522 RFID + PIR + TFT Display
 * Features: Built-in WiFi, RTC, superior performance
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

// WiFi credentials
char ssid[] = "YOUR_WIFI_SSID";
char password[] = "YOUR_WIFI_PASSWORD";
char server[] = "your-server.com";

WiFiClient wifi;
HttpClient client = HttpClient(wifi, server, 80);

// System variables
bool systemActive = false;
unsigned long lastMotionTime = 0;
unsigned long rfidActiveWindow = 10000; // 10 seconds
bool pirTriggered = false;
bool wifiConnected = false;
bool rtcInitialized = false;

// Student structure
struct Student {
  String uid;
  String regNo;
  String name;
  String className;
  String parentEmail;
  bool isPresent;
  String entryTime;
  String exitTime;
  bool isValid;
};

// Sample student database (replace with server calls)
Student students[] = {
  {"04:52:F4:2A", "REG001", "John Doe", "10A", "parent1@email.com", false, "", ""},
  {"04:63:A5:3B", "REG002", "Jane Smith", "10A", "parent2@email.com", false, "", ""},
  {"04:A1:B2:C3", "REG003", "Mike Johnson", "10B", "parent3@email.com", false, "", ""},
  {"04:D4:E5:F6", "REG004", "Sarah Wilson", "10B", "parent4@email.com", false, "", ""}
};
const int totalStudents = sizeof(students) / sizeof(students);

void setup() {
  Serial.begin(9600);
  
  // Initialize pins
  pinMode(PIR_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  
  // Initialize SPI
  SPI.begin();
  mfrc522.PCD_Init();
  
  // Initialize TFT display
  tft.begin();
  tft.setRotation(3);
  tft.fillScreen(ILI9341_BLACK);
  displayWelcome();
  
  // Initialize RTC
  initializeRTC();
  
  // Connect to WiFi
  connectToWiFi();
  
  // Sync time with NTP if WiFi connected
  if (wifiConnected) {
    syncTimeWithNTP();
  }
  
  Serial.println("Arduino UNO R4 WiFi Attendance System Ready");
  displayReady();
}

void loop() {
  // Check PIR sensor
  if (digitalRead(PIR_PIN) == HIGH && !pirTriggered) {
    pirTriggered = true;
    systemActive = true;
    lastMotionTime = millis();
    
    displayScanMessage();
    Serial.println("Motion detected - RFID activated");
  }
  
  // RFID reading window
  if (systemActive && (millis() - lastMotionTime < rfidActiveWindow)) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String rfidUID = getRFIDString();
      processAttendanceByUID(rfidUID);
      
      mfrc522.PICC_HaltA();
      systemActive = false;
      pirTriggered = false;
    }
  } else if (systemActive) {
    // Timeout - no card detected
    systemActive = false;
    pirTriggered = false;
    displayTimeout();
    delay(2000);
    displayReady();
  }
  
  // Reset PIR trigger after motion stops
  if (pirTriggered && digitalRead(PIR_PIN) == LOW) {
    delay(2000); // Debounce
    if (digitalRead(PIR_PIN) == LOW) {
      pirTriggered = false;
    }
  }
  
  delay(100);
}

void initializeRTC() {
  if (RTC.begin()) {
    Serial.println("RTC initialized successfully");
    rtcInitialized = true;
    
    // Set initial time (update this to current time)
    RTCTime startTime(8, Month::SEPTEMBER, 2025, 17, 50, 0, DayOfWeek::MONDAY, SaveLight::SAVING_TIME_ACTIVE);
    RTC.setTime(startTime);
  } else {
    Serial.println("RTC initialization failed");
    rtcInitialized = false;
  }
}

void connectToWiFi() {
  displayConnecting();
  Serial.println("Connecting to WiFi...");
  
  // Check for WiFi module
  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("Communication with WiFi module failed!");
    wifiConnected = false;
    return;
  }
  
  // Attempt to connect
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 10) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);
    
    WiFi.begin(ssid, password);
    delay(5000);
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.println("WiFi Connected!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
  } else {
    wifiConnected = false;
    Serial.println("WiFi connection failed - running in offline mode");
  }
}

void syncTimeWithNTP() {
  if (!wifiConnected) return;
  
  Serial.println("Syncing time with NTP server...");
  
  // Get NTP time (this is a simplified version)
  // In production, use a proper NTP library
  unsigned long epochTime = WiFi.getTime();
  
  if (epochTime > 0) {
    RTCTime timeToSet = RTCTime(epochTime);
    RTC.setTime(timeToSet);
    Serial.println("Time synced with NTP server");
  } else {
    Serial.println("Failed to get NTP time");
  }
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

void processAttendanceByUID(String rfidUID) {
  Serial.println("Processing UID: " + rfidUID);
  
  // Find student in local database
  int studentIndex = findStudent(rfidUID);
  
  if (studentIndex == -1) {
    // Unknown card - try server lookup if connected
    if (wifiConnected) {
      Student serverStudent = getStudentFromServer(rfidUID);
      if (serverStudent.isValid) {
        processValidStudent(serverStudent, rfidUID);
        return;
      }
    }
    
    displayError("Unknown Card");
    buzzerFail();
    delay(3000);
    displayReady();
    return;
  }
  
  processValidStudent(students[studentIndex], rfidUID);
}

void processValidStudent(Student &student, String rfidUID) {
  String currentTime = getCurrentTime();
  String currentDate = getCurrentDate();
  
  if (!student.isPresent) {
    // Entry
    student.isPresent = true;
    student.entryTime = currentTime;
    student.exitTime = "";
    
    displaySuccess("Welcome " + student.name, "Entry: " + currentTime);
    buzzerSuccess();
    digitalWrite(GREEN_LED, HIGH);
    
    // Log to server
    if (wifiConnected) {
      logAttendanceToServer(student, "ENTRY", currentTime, currentDate);
    }
    
    delay(3000);
    digitalWrite(GREEN_LED, LOW);
    
  } else {
    // Exit
    student.isPresent = false;
    student.exitTime = currentTime;
    
    displaySuccess("Goodbye " + student.name, "Exit: " + currentTime);
    buzzerSuccess();
    digitalWrite(GREEN_LED, HIGH);
    
    // Log to server
    if (wifiConnected) {
      logAttendanceToServer(student, "EXIT", currentTime, currentDate);
    }
    
    delay(3000);
    digitalWrite(GREEN_LED, LOW);
  }
  
  displayReady();
}

int findStudent(String rfidUID) {
  for (int i = 0; i < totalStudents; i++) {
    if (students[i].uid == rfidUID) {
      return i;
    }
  }
  return -1;
}

Student getStudentFromServer(String uid) {
  Student student;
  student.isValid = false;
  
  if (!wifiConnected) return student;
  
  // Make HTTP GET request
  String endpoint = "/attendance/student?uid=" + uid;
  
  client.beginRequest();
  client.get(endpoint);
  client.endRequest();
  
  int statusCode = client.responseStatusCode();
  String response = client.responseBody();
  
  if (statusCode == 200) {
    // Parse JSON response
    StaticJsonDocument<400> doc;
    deserializeJson(doc, response);
    
    if (doc["found"] == true) {
      student.uid = uid;
      student.regNo = doc["reg_no"].as<String>();
      student.name = doc["name"].as<String>();
      student.className = doc["class"].as<String>();
      student.parentEmail = doc["parent_email"].as<String>();
      student.isPresent = doc["is_present"].as<bool>();
      student.entryTime = doc["entry_time"].as<String>();
      student.exitTime = doc["exit_time"].as<String>();
      student.isValid = true;
    }
  }
  
  return student;
}

void logAttendanceToServer(Student &student, String action, String timestamp, String date) {
  if (!wifiConnected) return;
  
  // Prepare JSON data
  StaticJsonDocument<400> doc;
  doc["rfid_uid"] = student.uid;
  doc["reg_no"] = student.regNo;
  doc["name"] = student.name;
  doc["class"] = student.className;
  doc["action"] = action;
  doc["timestamp"] = timestamp;
  doc["date"] = date;
  
  String jsonString;
  serializeJson(doc, jsonString);
  
  // Send HTTP POST request
  client.beginRequest();
  client.post("/attendance/log");
  client.sendHeader("Content-Type", "application/json");
  client.sendHeader("Content-Length", jsonString.length());
  client.print(jsonString);
  client.endRequest();
  
  int statusCode = client.responseStatusCode();
  Serial.println("Server response: " + String(statusCode));
}

String getCurrentTime() {
  if (rtcInitialized) {
    RTCTime currentTime;
    RTC.getTime(currentTime);
    
    char timeString[21];
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
    
    char timeString[21];
    sprintf(timeString, "%02lu:%02lu:%02lu", hours, minutes, seconds);
    return String(timeString);
  }
}

String getCurrentDate() {
  if (rtcInitialized) {
    RTCTime currentTime;
    RTC.getTime(currentTime);
    
    char dateString[22];
    sprintf(dateString, "%04d-%02d-%02d", 
            currentTime.getYear(), 
            Month2int(currentTime.getMonth()), 
            currentTime.getDayOfMonth());
    return String(dateString);
  } else {
    return "2025-09-08"; // Default date
  }
}

// Display Functions
void displayWelcome() {
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(50, 60);
  tft.println("Attendance");
  tft.setCursor(70, 90);
  tft.println("System");
  tft.setTextSize(1);
  tft.setCursor(40, 140);
  tft.println("Arduino UNO R4 WiFi");
  tft.setCursor(60, 160);
  tft.println("Made in India");
  tft.setCursor(30, 180);
  tft.println("RA4M1 + ESP32-S3 + RTC");
  tft.setCursor(80, 200);
  tft.println("Initializing...");
}

void displayConnecting() {
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextColor(ILI9341_YELLOW);
  tft.setTextSize(2);
  tft.setCursor(40, 100);
  tft.println("Connecting");
  tft.setCursor(60, 130);
  tft.println("to WiFi...");
  
  tft.setTextSize(1);
  tft.setCursor(50, 170);
  tft.println("ESP32-S3 Module");
}

void displayReady() {
  tft.fillScreen(ILI9341_GREEN);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(3);
  tft.setCursor(80, 60);
  tft.println("READY");
  
  // Show current time
  tft.setTextSize(2);
  tft.setCursor(60, 100);
  tft.println(getCurrentTime());
  
  tft.setTextSize(1);
  tft.setCursor(60, 130);
  tft.println("Approach the reader");
  tft.setCursor(90, 150);
  tft.println("with your card");
  
  // Show status
  tft.setCursor(10, 190);
  if (wifiConnected) {
    tft.setTextColor(ILI9341_WHITE);
    tft.println("WiFi: Online");
  } else {
    tft.setTextColor(ILI9341_YELLOW);
    tft.println("WiFi: Offline");
  }
  
  tft.setCursor(10, 210);
  if (rtcInitialized) {
    tft.setTextColor(ILI9341_WHITE);
    tft.println("RTC: Active");
  } else {
    tft.setTextColor(ILI9341_YELLOW);
    tft.println("RTC: Simulated");
  }
}

void displayScanMessage() {
  tft.fillScreen(ILI9341_BLUE);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(50, 80);
  tft.println("Motion");
  tft.setCursor(40, 110);
  tft.println("Detected");
  tft.setTextSize(1);
  tft.setCursor(60, 150);
  tft.println("Please show your");
  tft.setCursor(90, 170);
  tft.println("RFID card");
}

void displaySuccess(String line1, String line2) {
  tft.fillScreen(ILI9341_GREEN);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(20, 50);
  tft.println("SUCCESS");
  tft.setTextSize(1);
  tft.setCursor(10, 100);
  tft.println(line1);
  tft.setCursor(10, 120);
  tft.println(line2);
  tft.setCursor(10, 150);
  tft.println("Date: " + getCurrentDate());
  
  // Show sync status
  tft.setCursor(10, 180);
  if (wifiConnected) {
    tft.println("Synced to server");
  } else {
    tft.println("Stored locally");
  }
}

void displayError(String message) {
  tft.fillScreen(ILI9341_RED);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(60, 80);
  tft.println("ERROR");
  tft.setTextSize(1);
  tft.setCursor(50, 120);
  tft.println(message);
  tft.setCursor(30, 150);
  tft.println("Please register this");
  tft.setCursor(50, 170);
  tft.println("card first");
  digitalWrite(RED_LED, HIGH);
  delay(2000);
  digitalWrite(RED_LED, LOW);
}

void displayTimeout() {
  tft.fillScreen(ILI9341_ORANGE);
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(40, 100);
  tft.println("TIMEOUT");
  tft.setTextSize(1);
  tft.setCursor(70, 140);
  tft.println("No card detected");
}

// Buzzer Functions
void buzzerSuccess() {
  digitalWrite(BUZZER_PIN, HIGH);
  delay(200);
  digitalWrite(BUZZER_PIN, LOW);
}

void buzzerFail() {
  for (int i = 0; i < 2; i++) {
    digitalWrite(BUZZER_PIN, HIGH);
    delay(200);
    digitalWrite(BUZZER_PIN, LOW);
    delay(200);
  }
}
