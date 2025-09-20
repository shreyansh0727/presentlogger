#include <MCUFRIEND_kbv.h>

MCUFRIEND_kbv tft;

// Common colors
#define BLACK 0x0000
#define BLUE 0x001F
#define RED 0xF800
#define GREEN 0x07E0
#define WHITE 0xFFFF
#define YELLOW 0xFFE0
#define ORANGE 0xFD80

void setup() {
  Serial.begin(9600); // Ensure matches Master UART baud rate
  tft.begin();
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
    if (payload == "WELCOME") screenWelcome();
    else if (payload == "READY") screenReady();
    else if (payload == "SCAN_MOTION") screenScanMessage();
    else if (payload == "DUPLICATE") screenDuplicate();
    else if (payload == "TIMEOUT") screenTimeout();
    else if (payload.startsWith("SUCCESS")) screenSuccess(payload.substring(8));
    else if (payload.startsWith("LATE")) screenLateArrival(payload.substring(5));
    else if (payload.startsWith("ERROR")) screenError(payload.substring(6));
  }
}

void screenWelcome() {
  tft.fillScreen(BLACK);
  tft.setTextColor(CYAN);
  tft.setTextSize(2);
  tft.setCursor(20, 30);
  tft.println("Enhanced");
  tft.setCursor(20, 60);
  tft.println("Attendance");
  tft.setCursor(40, 90);
  tft.println("System v2.0");
  tft.setTextColor(WHITE);
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

void screenReady() {
  tft.fillScreen(GREEN);
  tft.setTextColor(WHITE);
  tft.setTextSize(3);
  tft.setCursor(60, 25);
  tft.println("READY");
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
}

void screenScanMessage() {
  tft.fillScreen(BLUE);
  tft.setTextColor(WHITE);
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
  tft.setTextColor(BLACK);
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
  tft.setTextColor(WHITE);
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
  // Expected format: Name,Class,RegNo,Action,Time,Date
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
  tft.setTextColor(WHITE);
  tft.setTextSize(2);
  tft.setCursor(50, 20);
  tft.println("SUCCESS");
  tft.setTextSize(1);
  tft.setCursor(10, 60);
  tft.println(name);
  tft.setCursor(10, 80);
  tft.println(className);
  tft.setCursor(10, 100);
  tft.println(regNo);
  tft.setCursor(10, 120);
  tft.println(action);
  tft.setCursor(10, 140);
  tft.println(time);
  tft.setCursor(10, 160);
  tft.println(date);
  delay(3000);
  screenReady();
}

void screenLateArrival(String payload) {
  // Expected format: Name,Time
  int sep = payload.indexOf(',');
  String name = payload.substring(0, sep);
  String time = payload.substring(sep+1);

  tft.fillScreen(ORANGE);
  tft.setTextColor(WHITE);
  tft.setTextSize(2);
  tft.setCursor(30, 20);
  tft.println("LATE ARRIVAL");
  tft.setTextSize(1);
  tft.setCursor(10, 60);
  tft.println("Student: " + name);
  tft.setCursor(10, 80);
  tft.println("Arrival: " + time);
  tft.setCursor(10, 100);
  tft.println("Parent notification sent");
  delay(3000);
  screenReady();
}

void screenError(String payload) {
  // Expected format: Title,Message
  int sep = payload.indexOf(',');
  String title = payload.substring(0, sep);
  String msg = payload.substring(sep+1);

  tft.fillScreen(RED);
  tft.setTextColor(WHITE);
  tft.setTextSize(2);
  tft.setCursor(70, 50);
  tft.println("ERROR");
  tft.setTextSize(1);
  tft.setCursor(30, 90);
  tft.println(title);
  tft.setCursor(20, 110);
  tft.println(msg);
  delay(3000);
  screenReady();
}

// Placeholder functions for RTC or replacement on slave, if desired to show
String getCurrentTime() {
  return "--:--:--"; // Slave can use RTC or receive time from master via UART if desired
}
String getCurrentDate() {
  return "----/--/--";
}
