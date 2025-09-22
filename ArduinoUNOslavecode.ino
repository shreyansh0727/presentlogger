#include <MCUFRIEND_kbv.h>

MCUFRIEND_kbv tft;

// Color definitions
#define BLACK   0x0000
#define BLUE    0x001F
#define RED     0xF800
#define GREEN   0x07E0
#define CYAN    0x07FF
#define WHITE   0xFFFF
#define YELLOW  0xFFE0
#define ORANGE  0xFD80

// Status variables
String wifiStatus = "Unknown";
String serverStatus = "Unknown";
String rfidStatus = "Unknown";
String currentTime = "--:--:--";
String currentDate = "----/--/--";
String currentScreen = "WELCOME";
int dailyScans = 0;

void setup() {
  Serial.begin(9600);
  uint16_t ID = tft.readID();
  tft.begin(ID);
  tft.setRotation(3);
  screenWelcome();
}

void loop() {
  if (Serial.available()) {
    String message = Serial.readStringUntil('\n');
    message.trim();
    parseMessage(message);
  }
}

void parseMessage(String msg) {
  if (msg.length() == 0) return;

  int sep = msg.indexOf(':');
  if (sep == -1) return;

  String cmd = msg.substring(0, sep);
  String payload = msg.substring(sep + 1);

  if (cmd == "SCREEN") {
    if (payload == "WELCOME") {
      currentScreen = "WELCOME";
      screenWelcome();
    }
    else if (payload == "CONNECTING") {
      currentScreen = "CONNECTING";
      screenConnecting();
    }
    else if (payload == "READY") {
      currentScreen = "READY";
      screenReady();
    }
    else if (payload == "SCAN_MOTION") {
      currentScreen = "SCAN_MOTION";
      screenScanMessage();
    }
    else if (payload == "DUPLICATE") {
      currentScreen = "DUPLICATE";
      screenDuplicate();
    }
    else if (payload == "TIMEOUT") {
      currentScreen = "TIMEOUT";
      screenTimeout();
    }
    else if (payload.startsWith("SUCCESS")) {
      currentScreen = "SUCCESS";
      screenSuccess(payload.substring(8));
    }
    else if (payload.startsWith("LATE")) {
      currentScreen = "LATE";
      screenLateArrival(payload.substring(5));
    }
    else if (payload.startsWith("ERROR")) {
      currentScreen = "ERROR";
      screenError(payload.substring(6));
    }
  }
  else if (cmd == "STATUS") {
    parseStatusUpdate(payload);
  }
  else if (cmd == "INFO") {
    parseInfoUpdate(payload);
  }
}

void parseStatusUpdate(String payload) {
  if (payload.startsWith("WIFI:")) {
    wifiStatus = payload.substring(5);
  }
  else if (payload.startsWith("SERVER:")) {
    serverStatus = payload.substring(7);
  }
  else if (payload.startsWith("RFID:")) {
    rfidStatus = payload.substring(5);
  }
  if (currentScreen == "READY") {
    screenReady();
  }
}

void parseInfoUpdate(String payload) {
  if (payload.startsWith("TIME:")) {
    currentTime = payload.substring(5);
  }
  else if (payload.startsWith("DATE:")) {
    currentDate = payload.substring(5);
  }
  else if (payload.startsWith("SCANS:")) {
    dailyScans = payload.substring(6).toInt();
  }
  if (currentScreen == "READY") {
    screenReady();
  }
}

void screenWelcome() {
  tft.fillScreen(BLACK);
  tft.setTextColor(CYAN, BLACK);
  tft.setTextSize(2);
  tft.setCursor(20, 30);
  tft.println("Enhanced");
  tft.setCursor(20, 60);
  tft.println("Attendance");
  tft.setCursor(40, 90);
  tft.println("System v2.0");
  tft.setTextColor(WHITE, BLACK);
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

void screenConnecting() {
  tft.fillScreen(BLACK);
  tft.setTextColor(YELLOW, BLACK);
  tft.setTextSize(2);
  tft.setCursor(30, 70);
  tft.println("Connecting");
  tft.setCursor(50, 100);
  tft.println("to WiFi...");
  tft.setTextSize(1);
  tft.setTextColor(WHITE, BLACK);
  tft.setCursor(40, 140);
  tft.println("Please wait...");
  tft.setCursor(45, 160);
  tft.println("Checking network");
  tft.setCursor(60, 180);
  tft.println("connectivity");
}

void screenReady() {
  tft.fillScreen(GREEN);
  tft.setTextColor(WHITE, GREEN);
  tft.setTextSize(3);
  tft.setCursor(60, 25);
  tft.println("READY");
  
  // Time and date
  tft.setTextSize(2);
  tft.setCursor(50, 65);
  tft.println(currentTime);
  tft.setTextSize(1);
  tft.setCursor(70, 90);
  tft.println(currentDate);
  
  tft.setCursor(40, 115);
  tft.println("Approach the reader");
  tft.setCursor(60, 135);
  tft.println("with your card");

  // Status indicators
  tft.setCursor(5, 160);
  tft.setTextColor(wifiStatus == "Connected" ? WHITE : RED, GREEN);
  tft.println("WiFi: " + wifiStatus);

  tft.setCursor(5, 180);
  tft.setTextColor(serverStatus == "Online" ? WHITE : RED, GREEN);
  tft.println("Server: " + serverStatus);

  tft.setCursor(5, 200);
  tft.setTextColor(rfidStatus == "Connected" ? WHITE : RED, GREEN);
  tft.println("RFID: " + rfidStatus);

  tft.setCursor(5, 220);
  tft.setTextColor(WHITE, GREEN);
  tft.println("Scans Today: " + String(dailyScans));
}

void screenScanMessage() {
  tft.fillScreen(BLUE);
  tft.setTextColor(WHITE, BLUE);
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
}

void screenDuplicate() {
  tft.fillScreen(YELLOW);
  tft.setTextColor(BLACK, YELLOW);
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

void screenTimeout() {
  tft.fillScreen(ORANGE);
  tft.setTextColor(WHITE, ORANGE);
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

void screenSuccess(String payload) {
  int idx[5];
  idx[0] = payload.indexOf(',');
  idx[1] = payload.indexOf(',', idx[0]+1);
  idx[2] = payload.indexOf(',', idx[1]+1);
  idx[3] = payload.indexOf(',', idx[2]+1);
  idx[4] = payload.indexOf(',', idx[3]+1);
  
  String name = payload.substring(0, idx[0]);
  String className = payload.substring(idx[0]+1, idx[1]);
  String regNo = payload.substring(idx[1]+1, idx[2]);
  String action = payload.substring(idx[2]+1, idx[3]);
  String time = payload.substring(idx[3]+1, idx[4]);
  String date = payload.substring(idx[4]+1);

  tft.fillScreen(GREEN);
  tft.setTextColor(WHITE, GREEN);
  tft.setTextSize(2);
  tft.setCursor(50, 20);
  tft.println("SUCCESS");
  tft.setTextSize(1);
  tft.setCursor(10, 60);
  tft.println("Name: " + name);
  tft.setCursor(10, 80);
  tft.println("Class: " + className);
  tft.setCursor(10, 100);
  tft.println("Reg: " + regNo);
  tft.setCursor(10, 120);
  tft.println("Action: " + action);
  tft.setCursor(10, 140);
  tft.println("Time: " + time);
  
  // Show sync status
  tft.setCursor(10, 170);
  if (wifiStatus == "Connected" && serverStatus == "Online") {
    tft.println("Synced to Server");
    tft.setCursor(10, 190);
    tft.println("Real-time updated");
  } else {
    tft.setTextColor(YELLOW, GREEN);
    tft.println("Stored locally only");
  }
  
  delay(3000);
  screenReady();
  currentScreen = "READY";
}

void screenLateArrival(String payload) {
  int sep = payload.indexOf(',');
  String name = payload.substring(0, sep);
  String time = payload.substring(sep+1);
  
  tft.fillScreen(ORANGE);
  tft.setTextColor(WHITE, ORANGE);
  tft.setTextSize(2);
  tft.setCursor(30, 20);
  tft.println("LATE ARRIVAL");
  tft.setTextSize(1);
  tft.setCursor(10, 60);
  tft.println("Student: " + name);
  tft.setCursor(10, 80);
  tft.println("Arrival: " + time);
  tft.setCursor(10, 100);
  tft.println("Date: " + currentDate);
  tft.setTextColor(YELLOW, ORANGE);
  tft.setCursor(10, 130);
  tft.println("AFTER 9:15 AM");
  tft.setCursor(10, 150);
  tft.println("Parent notification sent");
  tft.setTextColor(WHITE, ORANGE);
  tft.setCursor(10, 180);
  tft.println("Recorded in system");
  
  delay(3000);
  screenReady();
  currentScreen = "READY";
}

void screenError(String payload) {
  int sep = payload.indexOf(',');
  String title = payload.substring(0, sep);
  String msg = payload.substring(sep+1);

  tft.fillScreen(RED);
  tft.setTextColor(WHITE, RED);
  tft.setTextSize(2);
  tft.setCursor(70, 50);
  tft.println("ERROR");
  tft.setTextSize(1);
  tft.setCursor(30, 90);
  tft.println(title);
  tft.setCursor(20, 110);
  tft.println(msg);
  
  if (title == "Unknown Card") {
    tft.setCursor(15, 140);
    tft.println("Register this card in");
    tft.setCursor(25, 160);
    tft.println("Flask Dashboard");
  } else if (title.indexOf("WiFi") >= 0) {
    tft.setCursor(25, 140);
    tft.println("Check network settings");
    tft.setCursor(35, 160);
    tft.println("Restart if needed");
  } else if (title.indexOf("RFID") >= 0) {
    tft.setCursor(15, 140);
    tft.println("Check RFID reader");
    tft.setCursor(25, 160);
    tft.println("wiring and power");
  } else {
    tft.setCursor(20, 140);
    tft.println("Check Flask server");
    tft.setCursor(30, 160);
    tft.println("status and API key");
  }
  
  delay(3000);
  screenReady();
  currentScreen = "READY";
}
