# ESP32 Wi-Fi Security Monitor — Installation & Usage

This project is intended for educational and authorized security research purposes.

This guide explains how to install and use the ESP32 Wi-Fi Security Monitor on Windows and Kali Linux.

Choose your operating system and follow the steps in order.

---

# 🪟 Windows Installation

## 1. Install Required Software

Install these:

- Git
- Node.js (LTS)
- Arduino IDE

Official websites:

- Git: https://git-scm.com/download/win
- Node.js: https://nodejs.org/
- Arduino IDE: https://www.arduino.cc/en/software

After installing Git and Node.js, verify:

```bash
git --version
node --version
npm --version
````

## 2. Install ESP32 Board Support

Open Arduino IDE.

Go to:

**File → Preferences**

Add the ESP32 Board Manager URL:

```text
https://espressif.github.io/arduino-esp32/package_esp32_index.json
```

Then go to:

**Tools → Board → Boards Manager**

Search for:

```text
ESP32
```

Install:

**esp32 by Espressif Systems**

## 3. Download the Project

Open **PowerShell** or **Command Prompt**:

```bash
git clone https://github.com/sachidanand2/esp32-security-monitor.git
cd esp32-security-monitor
```

## 4. Install Dashboard

```bash
npm install
```

## 5. Upload ESP32 Firmware

Open this file in Arduino IDE:

```text
esp32/ESP32_Security_Monitor/ESP32_Security_Monitor.ino
```

Connect the ESP32 using USB.

Select:

**Tools → Board → ESP32 Arduino → ESP32 Dev Module**

Then:

**Tools → Port → Your ESP32 COM Port**

Click **Upload**.

## 6. Connect to ESP32 Wi-Fi

Connect your computer to:

```text
Wi-Fi: ESP32-Security-Monitor
Password: ESP32monitor123
```

## 7. Start the Dashboard

Open the project folder in PowerShell or Command Prompt:

```bash
npm run dev
```

Open the `localhost` URL shown in the terminal.

---

# 🐧 Kali Linux Installation

## 1. Install Required Software

Open Terminal:

```bash
sudo apt update
sudo apt install git nodejs npm -y
```

Verify:

```bash
git --version
node --version
npm --version
```

Install **Arduino IDE** and ESP32 board support if they are not already installed.

## 2. Download the Project

```bash
git clone https://github.com/sachidanand2/esp32-security-monitor.git
cd esp32-security-monitor
```

## 3. Install Dashboard

```bash
npm install
```

## 4. Upload ESP32 Firmware

Open:

```text
esp32/ESP32_Security_Monitor/ESP32_Security_Monitor.ino
```

in Arduino IDE.

Select:

**ESP32 Dev Module → Correct USB Port → Upload**

## 5. Connect to ESP32 Wi-Fi

Connect your computer to:

```text
Wi-Fi: ESP32-Security-Monitor
Password: ESP32monitor123
```

## 6. Start the Dashboard

```bash
npm run dev
```

Open the `localhost` URL shown in the terminal.

---

# 💡 Important

First install **Git, Node.js, Arduino IDE, and ESP32 board support**.

After that, follow the steps using:

**Copy → Paste → Enter**

The computer running the React dashboard must be connected to the **ESP32-Security-Monitor** Wi-Fi network.

---

# ⚠️ Security Notice

Use this project only on Wi-Fi networks and devices you own or have permission to monitor.

This project is intended for educational and authorized security research purposes.

```
