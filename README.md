# esp32-file-tampering-detection
ESP32 based system that detects file tampering on SD card using SHA256 hashing and alerts via LED, buzzer and Blynk IoT.

A security system built using **ESP32**, **SD Card**, and **SPIFFS** that detects unauthorized changes in a file. If the monitored file is modified, the system triggers an **LED alert, buzzer alarm, and a Blynk IoT notification**.

This project ensures **data integrity** by continuously monitoring a file stored on an SD card using **SHA-256 hashing**.

---

## Features

- Detects unauthorized file modifications
- Uses **SHA-256 cryptographic hashing**
- LED and buzzer alarm for tampering
- Sends notification via **Blynk IoT**
- Secure file backup stored in **SPIFFS**
- Hardware **reset button to restore original file**
- Detects **firmware updates and resets backup automatically**
- Real-time SD card insertion/removal detection

---

## Hardware Requirements

- ESP32 Development Board
- SD Card Module
- Micro SD Card
- LED
- Buzzer
- Push Button
- Breadboard
- Jumper Wires
- WiFi Network

---

## Pin Configuration

| Component | ESP32 Pin |
|-----------|-----------|
| SD Card CS | GPIO 5 |
| SD Card SCK | GPIO 18 |
| SD Card MOSI | GPIO 23 |
| SD Card MISO | GPIO 19 |
| LED | GPIO 4 |
| Buzzer | GPIO 2 |
| Reset Button | GPIO 15 |

Reset button should be connected to **GND** (using INPUT_PULLUP).

---
## 🛠️ Hardware Setup

To build this project, connect the components as shown in the diagram below.

![Circuit Diagram](images/circuit%20diagram.png)
For more photos of the physical build, visit the [Images folder](./images).
## Software Requirements

- Arduino IDE
- ESP32 Board Package
- Blynk Library
- SD Library
- SPIFFS
- WiFi Library
- mbedTLS (SHA256)

---


## How the System Works

### First Boot
1. ESP32 reads `/secure.txt` from SD card.
2. A backup copy is stored in **SPIFFS flash memory**.
3. SHA-256 hash of the file is calculated.
4. This hash becomes the **baseline reference**.

### Monitoring Process
Every **1 second** the ESP32:

1. Reads `/secure.txt`
2. Calculates SHA-256 hash
3. Compares with stored baseline hash

If hashes match → File is secure.

If hashes differ → **Tampering detected**

---

## Tampering Alert

When tampering occurs:

- LED turns ON
- Buzzer activates
- Blynk sends a **tampering alert notification**

---

## Reset Button Function

Pressing the reset button will:

1. Restore the original file from SPIFFS backup
2. Rewrite `/secure.txt` on the SD card
3. Reset baseline hash
4. Turn off alarm

---

## Firmware Update Handling

When new firmware is uploaded:

1. System detects firmware ID change
2. Deletes old backup
3. Creates new backup from SD card

---

## File Location

Monitored file on SD card:

```
/secure.txt
```

Backup stored in ESP32 flash:

```
/secure_backup
```

---

## Example Use Cases

- Secure data logging
- Evidence storage systems
- Industrial monitoring
- Document integrity verification
- IoT security applications

---

## Future Improvements

- Monitor multiple files
- Cloud backup support
- Mobile application interface
- Email/SMS alerts
- Encryption of stored backups

---

## Author
Adeel Ahmed Latif


