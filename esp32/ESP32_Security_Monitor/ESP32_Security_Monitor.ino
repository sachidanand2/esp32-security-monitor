#include <WiFi.h>
#include <WebServer.h>

#define AP_SSID "ESP32-Security-Monitor"
#define AP_PASSWORD "twintech443"

#define MAX_NETWORKS 50
#define MAX_EVENTS 40

#define SCAN_INTERVAL 10000

WebServer server(80);

struct NetworkInfo {
  String ssid;
  String bssid;
  int rssi;
  int channel;
  wifi_auth_mode_t security;

  int riskScore;
  String riskLevel;
  String riskReason;
};

struct SecurityEvent {
  String type;
  String ssid;
  String bssid;
  int oldRSSI;
  int newRSSI;
  int channel;
  unsigned long timestamp;
};

NetworkInfo currentNetworks[MAX_NETWORKS];
NetworkInfo previousNetworks[MAX_NETWORKS];

SecurityEvent events[MAX_EVENTS];

int currentCount = 0;
int previousCount = 0;
int eventCount = 0;

int scanCount = 0;
int openCount = 0;
int securedCount = 0;

unsigned long lastScan = 0;


// =====================================================
// SECURITY NAME
// =====================================================

String securityName(wifi_auth_mode_t auth) {

  switch (auth) {

    case WIFI_AUTH_OPEN:
      return "OPEN";

    case WIFI_AUTH_WEP:
      return "WEP";

    case WIFI_AUTH_WPA_PSK:
      return "WPA";

    case WIFI_AUTH_WPA2_PSK:
      return "WPA2";

    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA/WPA2";

    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA2-ENTERPRISE";

    case WIFI_AUTH_WPA3_PSK:
      return "WPA3";

    case WIFI_AUTH_WPA2_WPA3_PSK:
      return "WPA2/WPA3";

    default:
      return "UNKNOWN";
  }
}


// =====================================================
// SIGNAL
// =====================================================

String signalLevel(int rssi) {

  if (rssi >= -50)
    return "Excellent";

  if (rssi >= -60)
    return "Good";

  if (rssi >= -70)
    return "Fair";

  return "Weak";
}


int signalPercent(int rssi) {

  int percent = 2 * (rssi + 100);

  if (percent < 0)
    percent = 0;

  if (percent > 100)
    percent = 100;

  return percent;
}


// =====================================================
// FIND NETWORK
// =====================================================

int findNetwork(
  NetworkInfo arr[],
  int count,
  String bssid
) {

  for (int i = 0; i < count; i++) {

    if (arr[i].bssid == bssid)
      return i;
  }

  return -1;
}


// =====================================================
// HTML ESCAPE
// =====================================================

String jsonEscape(String input) {

  input.replace("\\", "\\\\");
  input.replace("\"", "\\\"");
  input.replace("\n", "\\n");
  input.replace("\r", "\\r");

  return input;
}


// =====================================================
// EVENT
// =====================================================

void addEvent(
  String type,
  String ssid,
  String bssid,
  int oldRSSI,
  int newRSSI,
  int channel
) {

  if (eventCount < MAX_EVENTS) {

    events[eventCount].type = type;
    events[eventCount].ssid = ssid;
    events[eventCount].bssid = bssid;
    events[eventCount].oldRSSI = oldRSSI;
    events[eventCount].newRSSI = newRSSI;
    events[eventCount].channel = channel;
    events[eventCount].timestamp = millis();

    eventCount++;

  } else {

    for (int i = 0; i < MAX_EVENTS - 1; i++)
      events[i] = events[i + 1];

    events[MAX_EVENTS - 1].type = type;
    events[MAX_EVENTS - 1].ssid = ssid;
    events[MAX_EVENTS - 1].bssid = bssid;
    events[MAX_EVENTS - 1].oldRSSI = oldRSSI;
    events[MAX_EVENTS - 1].newRSSI = newRSSI;
    events[MAX_EVENTS - 1].channel = channel;
    events[MAX_EVENTS - 1].timestamp = millis();
  }
}


// =====================================================
// RISK ENGINE
// =====================================================

void calculateRisk(NetworkInfo &net, bool isNew, int rssiChange) {

  int score = 0;

  String reason = "";

  // OPEN NETWORK
  if (net.security == WIFI_AUTH_OPEN) {

    score += 40;

    reason += "Open network; ";
  }


  // WEP
  if (net.security == WIFI_AUTH_WEP) {

    score += 35;

    reason += "Weak WEP security; ";
  }


  // VERY STRONG SIGNAL
  if (net.rssi >= -40) {

    score += 15;

    reason += "Very strong signal; ";
  }


  // NEW NETWORK
  if (isNew) {

    score += 20;

    reason += "New network detected; ";
  }


  // RSSI CHANGE
  if (abs(rssiChange) >= 15) {

    score += 15;

    reason += "Significant RSSI change; ";
  }


  if (score > 100)
    score = 100;


  net.riskScore = score;


  if (score >= 70)
    net.riskLevel = "HIGH";

  else if (score >= 40)
    net.riskLevel = "MEDIUM";

  else
    net.riskLevel = "LOW";


  if (reason == "")
    reason = "No major risk indicators";


  net.riskReason = reason;
}


// =====================================================
// PERFORM SCAN
// =====================================================

void performScan() {

  Serial.println();
  Serial.println("======================================");
  Serial.println("V9 WIFI SECURITY SCAN");
  Serial.println("======================================");

  previousCount = currentCount;

  for (int i = 0; i < previousCount; i++)
    previousNetworks[i] = currentNetworks[i];


  int found = WiFi.scanNetworks(
    false,
    true
  );


  currentCount = 0;

  openCount = 0;
  securedCount = 0;

  scanCount++;


  for (int i = 0;
       i < found && currentCount < MAX_NETWORKS;
       i++) {

    NetworkInfo &net = currentNetworks[currentCount];


    String ssid = WiFi.SSID(i);

    if (ssid.length() == 0)
      ssid = "<HIDDEN>";


    net.ssid = ssid;

    net.bssid = WiFi.BSSIDstr(i);

    net.rssi = WiFi.RSSI(i);

    net.channel = WiFi.channel(i);

    net.security = WiFi.encryptionType(i);


    if (net.security == WIFI_AUTH_OPEN)
      openCount++;
    else
      securedCount++;


    int previousIndex =
      findNetwork(
        previousNetworks,
        previousCount,
        net.bssid
      );


    bool isNew = previousIndex == -1;

    int rssiChange = 0;


    if (!isNew) {

      rssiChange =
        net.rssi -
        previousNetworks[previousIndex].rssi;


      if (abs(rssiChange) >= 10) {

        addEvent(
          "RSSI_CHANGE",
          net.ssid,
          net.bssid,
          previousNetworks[previousIndex].rssi,
          net.rssi,
          net.channel
        );
      }

    } else {

      if (previousCount > 0) {

        addEvent(
          "NEW_NETWORK",
          net.ssid,
          net.bssid,
          0,
          net.rssi,
          net.channel
        );
      }
    }


    calculateRisk(
      net,
      isNew,
      rssiChange
    );


    currentCount++;
  }


  // DISAPPEARED NETWORKS

  for (int i = 0; i < previousCount; i++) {

    int index =
      findNetwork(
        currentNetworks,
        currentCount,
        previousNetworks[i].bssid
      );


    if (index == -1) {

      addEvent(
        "DISAPPEARED",
        previousNetworks[i].ssid,
        previousNetworks[i].bssid,
        previousNetworks[i].rssi,
        0,
        previousNetworks[i].channel
      );
    }
  }


  // SERIAL OUTPUT

  for (int i = 0; i < currentCount; i++) {

    Serial.println();

    Serial.print("SSID: ");
    Serial.println(currentNetworks[i].ssid);

    Serial.print("BSSID: ");
    Serial.println(currentNetworks[i].bssid);

    Serial.print("RSSI: ");
    Serial.print(currentNetworks[i].rssi);
    Serial.println(" dBm");

    Serial.print("Signal: ");
    Serial.println(
      signalLevel(currentNetworks[i].rssi)
    );

    Serial.print("Channel: ");
    Serial.println(currentNetworks[i].channel);

    Serial.print("Security: ");
    Serial.println(
      securityName(
        currentNetworks[i].security
      )
    );

    Serial.print("Risk: ");
    Serial.print(currentNetworks[i].riskScore);
    Serial.print(" / ");
    Serial.println(currentNetworks[i].riskLevel);
  }


  WiFi.scanDelete();

  Serial.println();
  Serial.println("Scan completed.");
}


// =====================================================
// JSON API
// =====================================================

void handleAPIData() {

  String json = "{";

  json += "\"scanCount\":";
  json += String(scanCount);

  json += ",\"networkCount\":";
  json += String(currentCount);

  json += ",\"openCount\":";
  json += String(openCount);

  json += ",\"securedCount\":";
  json += String(securedCount);


  // NETWORKS

  json += ",\"networks\":[";


  for (int i = 0; i < currentCount; i++) {

    if (i > 0)
      json += ",";


    NetworkInfo &net =
      currentNetworks[i];


    json += "{";


    json += "\"ssid\":\"";
    json += jsonEscape(net.ssid);
    json += "\"";


    json += ",\"bssid\":\"";
    json += net.bssid;
    json += "\"";


    json += ",\"rssi\":";
    json += String(net.rssi);


    json += ",\"signal\":\"";
    json += signalLevel(net.rssi);
    json += "\"";


    json += ",\"signalPercent\":";
    json += String(
      signalPercent(net.rssi)
    );


    json += ",\"channel\":";
    json += String(net.channel);


    json += ",\"security\":\"";
    json += securityName(net.security);
    json += "\"";


    json += ",\"riskScore\":";
    json += String(net.riskScore);


    json += ",\"riskLevel\":\"";
    json += net.riskLevel;
    json += "\"";


    json += ",\"riskReason\":\"";
    json += jsonEscape(net.riskReason);
    json += "\"";


    json += "}";
  }


  json += "]";


  // EVENTS

  json += ",\"events\":[";


  for (int i = 0; i < eventCount; i++) {

    if (i > 0)
      json += ",";


    json += "{";


    json += "\"type\":\"";
    json += events[i].type;
    json += "\"";


    json += ",\"ssid\":\"";
    json += jsonEscape(events[i].ssid);
    json += "\"";


    json += ",\"bssid\":\"";
    json += events[i].bssid;
    json += "\"";


    json += ",\"oldRSSI\":";
    json += String(events[i].oldRSSI);


    json += ",\"newRSSI\":";
    json += String(events[i].newRSSI);


    json += ",\"channel\":";
    json += String(events[i].channel);


    json += ",\"time\":";
    json += String(events[i].timestamp);


    json += "}";
  }


  json += "]";


  json += "}";


  server.sendHeader(
    "Access-Control-Allow-Origin",
    "*"
  );


  server.send(
    200,
    "application/json",
    json
  );
}


// =====================================================
// MANUAL SCAN API
// =====================================================

void handleScan() {

  performScan();


  server.sendHeader(
    "Access-Control-Allow-Origin",
    "*"
  );


  server.send(
    200,
    "application/json",
    "{\"status\":\"scan_completed\"}"
  );
}


// =====================================================
// ROOT
// =====================================================

void handleRoot() {

  server.sendHeader(
    "Access-Control-Allow-Origin",
    "*"
  );


  server.send(
    200,
    "text/plain",
    "ESP32 V9 Security Monitor API"
  );
}


// =====================================================
// SETUP
// =====================================================

void setup() {

  Serial.begin(115200);

  delay(1000);


  WiFi.mode(WIFI_AP_STA);


  WiFi.softAP(
    AP_SSID,
    AP_PASSWORD
  );


  Serial.println();
  Serial.println("======================================");
  Serial.println("ESP32 V9 SECURITY MONITOR");
  Serial.println("======================================");

  Serial.print("AP SSID: ");
  Serial.println(AP_SSID);

  Serial.print("Dashboard/API IP: ");
  Serial.println(
    WiFi.softAPIP()
  );


  performScan();


  server.on(
    "/",
    handleRoot
  );


  server.on(
    "/api/data",
    HTTP_GET,
    handleAPIData
  );


  server.on(
    "/api/scan",
    HTTP_GET,
    handleScan
  );


  server.begin();


  Serial.println("HTTP server started.");
}


// =====================================================
// LOOP
// =====================================================

void loop() {

  server.handleClient();


  if (
    millis() - lastScan >=
    SCAN_INTERVAL
  ) {

    lastScan = millis();

    performScan();
  }
}
