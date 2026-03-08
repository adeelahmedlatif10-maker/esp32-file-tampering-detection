// ESP32 File Tampering Detection with SD + SPIFFS backup
#define BLYNK_TEMPLATE_ID   "TMPL6Iaq7wY5b"
#define BLYNK_TEMPLATE_NAME "file tampering detection system"
#define BLYNK_AUTH_TOKEN    "DsDlg96XeTTRf_UrTu7_dxhzLb6l5LRZ"

#include <WiFi.h>
#include <WiFiClient.h>
#include <BlynkSimpleEsp32.h>
#include <SPI.h>
#include <SD.h>
#include "SPIFFS.h"
#include "mbedtls/sha256.h"

char ssid[] = "Amir";
char pass[] = "amir4567";


#define SD_CS    5
#define SD_SCK   18
#define SD_MOSI  23
#define SD_MISO  19

#define LED_PIN     4
#define BUZZER_PIN  2
#define RESET_BTN   15   

static const uint32_t SD_SPI_FREQ = 8000000UL; 

const char *MONITORED_FILE    = "/secure.txt";      
const char *FLASH_BACKUP_FILE = "/secure_backup";   
const char *FIRMWARE_ID_FILE  = "/firmware_id.txt"; 

bool sdMounted        = false;
bool alarmActive      = false;
bool notificationSent = false;
bool hasBackup        = false;

String baselineHash       = "";
String currentFirmwareId  = "";
String savedFirmwareId    = "";


String sha256OfString(const String &input) {
  uint8_t hash[32];

  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx,
                        reinterpret_cast<const unsigned char*>(input.c_str()),
                        input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  String hashStr;
  for (int i = 0; i < 32; i++) {
    if (hash[i] < 16) hashStr += "0";
    hashStr += String(hash[i], HEX);
  }
  hashStr.toUpperCase();
  return hashStr;
}

void triggerAlarm() {
  if (!alarmActive) {
    Serial.println(">>> TAMPER ALARM TRIGGERED <<<");
  }
  alarmActive = true;
  digitalWrite(LED_PIN, HIGH);
  digitalWrite(BUZZER_PIN, HIGH);

  if (!notificationSent) {
    Serial.println("Sending Blynk tampering_alert event...");
    Blynk.logEvent("tampering_alert", "Alert! File tampered!");
    notificationSent = true;
  }
}

void clearAlarm() {
  alarmActive = false;
  digitalWrite(LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);
  Serial.println("Alarm cleared (LED and buzzer OFF).");
}

String readSdFile(const char *path) {
  if (!sdMounted) {
    Serial.println("readSdFile: SD not mounted.");
    return "";
  }

  Serial.print("readSdFile: opening for READ: ");
  Serial.println(path);

  File f = SD.open(path, FILE_READ);
  if (!f && path[0] == '/') {
    Serial.println("readSdFile: first open failed, trying without leading '/'");
    f = SD.open(path + 1, FILE_READ);
  }
  if (!f) {
    Serial.println("readSdFile: FAILED to open file for read.");
    return "";
  }

  String content = f.readString();
  f.close();
  Serial.print("readSdFile: read ");
  Serial.print(content.length());
  Serial.println(" bytes.");
  return content;
}

bool writeSdFile(const char *path, const String &content) {
  if (!sdMounted) {
    Serial.println("writeSdFile: SD not mounted.");
    return false;
  }

  Serial.print("writeSdFile: removing old file: ");
  Serial.println(path);
  SD.remove(path);
  if (path[0] == '/') SD.remove(path + 1);

  Serial.print("writeSdFile: opening for WRITE: ");
  Serial.println(path);
  File f = SD.open(path, FILE_WRITE);
  if (!f && path[0] == '/') {
    Serial.println("writeSdFile: first open failed, trying without leading '/'");
    f = SD.open(path + 1, FILE_WRITE);
  }
  if (!f) {
    Serial.println("writeSdFile: FAILED to open file for write.");
    return false;
  }

  f.print(content);
  f.close();
  Serial.print("writeSdFile: wrote ");
  Serial.print(content.length());
  Serial.println(" bytes.");
  return true;
}

bool mountSD() {
  Serial.println("mountSD: initializing SPI and SD...");
  SPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if (!SD.begin(SD_CS, SPI, SD_SPI_FREQ)) {
    Serial.println("mountSD: SD.begin(..., SD_SPI_FREQ) FAILED, trying default SD.begin(SD_CS)...");
    if (!SD.begin(SD_CS)) {
      Serial.println("mountSD: SD.begin(SD_CS) FAILED.");
      return false;
    }
  }
  uint8_t cardType = SD.cardType();
  if (cardType == CARD_NONE) {
    Serial.println("mountSD: cardType == CARD_NONE.");
    return false;
  }
  Serial.print("mountSD: card type = ");
  if (cardType == CARD_MMC) Serial.println("MMC");
  else if (cardType == CARD_SD) Serial.println("SD");
  else if (cardType == CARD_SDHC) Serial.println("SDHC");
  else Serial.println("UNKNOWN");
  return true;
}

void checkSdState() {
  static unsigned long lastCheck = 0;
  unsigned long now = millis();
  if (now - lastCheck < 500) return; 
  lastCheck = now;

  if (!sdMounted) {
    if (mountSD()) {
      sdMounted = true;
      Serial.println("checkSdState: SD card INSERTED and mounted.");
    }
  } else {
    if (SD.cardType() == CARD_NONE) {
      sdMounted = false;
      Serial.println("checkSdState: SD card REMOVED.");
    }
  }
}

String loadFirmwareIdFromFlash() {
  Serial.println("Loading firmware ID from SPIFFS...");
  File f = SPIFFS.open(FIRMWARE_ID_FILE, FILE_READ);
  if (!f) {
    Serial.println("Firmware ID file not found.");
    return "";
  }
  String id = f.readString();
  f.close();
  id.trim();
  Serial.print("Loaded firmware ID: ");
  Serial.println(id);
  return id;
}

bool saveFirmwareIdToFlash(const String &id) {
  Serial.print("Saving firmware ID to SPIFFS: ");
  Serial.println(id);
  File f = SPIFFS.open(FIRMWARE_ID_FILE, FILE_WRITE);
  if (!f) {
    Serial.println("Failed to open firmware ID file for writing.");
    return false;
  }
  f.print(id);
  f.close();
  return true;
}

String loadBackupFromFlash() {
  Serial.println("Loading backup from SPIFFS...");
  File f = SPIFFS.open(FLASH_BACKUP_FILE, FILE_READ);
  if (!f) {
    Serial.println("Backup file not found in SPIFFS.");
    return "";
  }
  String content = f.readString();
  f.close();
  Serial.print("Loaded backup, size = ");
  Serial.println(content.length());
  return content;
}

bool saveBackupToFlash(const String &content) {
  Serial.print("Saving backup to SPIFFS, size = ");
  Serial.println(content.length());
  File f = SPIFFS.open(FLASH_BACKUP_FILE, FILE_WRITE);
  if (!f) {
    Serial.println("Failed to open backup file for writing in SPIFFS.");
    return false;
  }
  f.print(content);
  f.close();
  return true;
}

bool createBackupFromCurrentFile() {
  Serial.println("createBackupFromCurrentFile: reading monitored file from SD...");
  String content = readSdFile(MONITORED_FILE);
  if (content == "") {
    Serial.println("createBackupFromCurrentFile: monitored file not found or empty.");
    return false;
  }

  if (!saveBackupToFlash(content)) {
    Serial.println("createBackupFromCurrentFile: failed to save backup in SPIFFS.");
    return false;
  }

  baselineHash = sha256OfString(content);
  hasBackup = true;
  Serial.print("createBackupFromCurrentFile: new baseline hash = ");
  Serial.println(baselineHash);

  if (currentFirmwareId != "") {
    saveFirmwareIdToFlash(currentFirmwareId);
  }
  return true;
}

bool restoreFileFromBackup() {
  Serial.println("restoreFileFromBackup: starting...");
  if (!hasBackup) {
    Serial.println("restoreFileFromBackup: NO backup available.");
    return false;
  }
  if (!sdMounted) {
    Serial.println("restoreFileFromBackup: SD not mounted.");
    return false;
  }

  String backup = loadBackupFromFlash();
  if (backup == "") {
    Serial.println("restoreFileFromBackup: backup empty or unreadable.");
    return false;
  }

  if (!writeSdFile(MONITORED_FILE, backup)) {
    Serial.println("restoreFileFromBackup: FAILED to write file to SD.");
    return false;
  }

  baselineHash = sha256OfString(backup);
  Serial.print("restoreFileFromBackup: baseline reset to = ");
  Serial.println(baselineHash);
  return true;
}

void checkFileTamper() {
  static unsigned long lastCheck = 0;
  unsigned long now = millis();
  if (now - lastCheck < 1000) return; // check every 1000 ms
  lastCheck = now;

  if (!sdMounted) {
    Serial.println("checkFileTamper: SD not mounted, skipping.");
    return;
  }
  if (baselineHash == "") {
    Serial.println("checkFileTamper: no baseline yet, skipping.");
    return;
  }
  if (alarmActive) {
    Serial.println("checkFileTamper: alarm already active, skipping.");
    return;
  }

  Serial.println("checkFileTamper: reading monitored file from SD...");
  String content = readSdFile(MONITORED_FILE);
  if (content == "") {
    Serial.println("checkFileTamper: read returned empty (file missing or SD error) -> IGNORING this check.");
    return;
  }

  String currentHash = sha256OfString(content);
  Serial.print("checkFileTamper: current hash = ");
  Serial.println(currentHash);
  Serial.print("checkFileTamper: baseline     = ");
  Serial.println(baselineHash);

  if (currentHash != baselineHash) {
    Serial.println("checkFileTamper: TAMPER DETECTED (hash mismatch).");
    triggerAlarm();
  } else {
    Serial.println("checkFileTamper: file OK (no tamper).");
  }
}

void handleResetButton() {
  if (digitalRead(RESET_BTN) == LOW) {
    delay(50);
    if (digitalRead(RESET_BTN) == LOW) {
      Serial.println("handleResetButton: reset button pressed -> restore from backup.");
      if (restoreFileFromBackup()) {
        clearAlarm();
        notificationSent = false;
        Serial.println("handleResetButton: restore successful, alarm cleared.");
      } else {
        Serial.println("handleResetButton: restore FAILED.");
      }
      while (digitalRead(RESET_BTN) == LOW) {
        delay(10);
      }
    }
  }
}


void setup() {
  Serial.begin(115200);

  pinMode(LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(RESET_BTN, INPUT_PULLUP);
  clearAlarm();

  Serial.println();
  Serial.println("=== ESP32 File Tampering Detection ===");
  Serial.println("SD wiring: CS=5, SCK=18, MOSI=23, MISO=19");
  Serial.println("File on SD: /secure.txt");
  Serial.println("Reset button: GPIO 15 to GND");
  Serial.println("LED: GPIO 4, BUZZER: GPIO 2");

  currentFirmwareId = String(__DATE__) + " " + String(__TIME__);
  Serial.print("Current firmware ID: ");
  Serial.println(currentFirmwareId);

  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount FAILED. Backup will not persist.");
  } else {
    savedFirmwareId = loadFirmwareIdFromFlash();

    if (savedFirmwareId != "" && savedFirmwareId != currentFirmwareId) {
      Serial.println("Firmware changed -> deleting old backup and firmware ID.");
      SPIFFS.remove(FLASH_BACKUP_FILE);
      SPIFFS.remove(FIRMWARE_ID_FILE);
      savedFirmwareId = "";
    }

    String backup = loadBackupFromFlash();
    if (backup != "") {
      hasBackup = true;
      baselineHash = sha256OfString(backup);
      Serial.print("Loaded baseline hash from SPIFFS: ");
      Serial.println(baselineHash);
    } else {
      hasBackup = false;
      baselineHash = "";
      Serial.println("No backup in SPIFFS yet.");
    }
  }

  Serial.println("Connecting to WiFi & Blynk...");
  Blynk.begin(BLYNK_AUTH_TOKEN, ssid, pass);
  Serial.println("Blynk connected.");

  sdMounted = mountSD();
  if (sdMounted) {
    Serial.println("SD mounted OK.");
  } else {
    Serial.println("SD mount FAILED. Insert card / check wiring, then reset.");
  }

  if (sdMounted && !hasBackup) {
    Serial.println("No backup yet -> creating from current SD file...");
    if (!createBackupFromCurrentFile()) {
      Serial.println("Initial backup creation FAILED. Tamper detection will not work.");
    }
  }
}

void loop() {
  Blynk.run();
  checkSdState();      
  checkFileTamper();   
  handleResetButton(); 
}
