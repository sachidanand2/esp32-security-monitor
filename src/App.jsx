import { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";

const API_BASE = "http://192.168.4.1";
const TRACKED_SSID = "OPPO F31 PRO 5G";
const HISTORY_KEY = "esp32_security_v11_history";
const MAX_HISTORY = 60;

function loadHistory() {
  try {
    const saved = localStorage.getItem(HISTORY_KEY);
    return saved ? JSON.parse(saved) : [];
  } catch {
    return [];
  }
}

function securityClass(security = "") {
  const s = security.toUpperCase();

  if (s.includes("OPEN") || s.includes("NONE")) return "open";
  if (s.includes("WEP")) return "wep";
  if (s.includes("WPA3")) return "wpa3";
  if (s.includes("WPA2")) return "wpa2";
  if (s.includes("WPA")) return "wpa";

  return "unknown";
}

function formatTime(timestamp) {
  if (!timestamp) return "--";

  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatDate(timestamp) {
  if (!timestamp) return "--";

  return new Date(timestamp).toLocaleString();
}

function priorityClass(priority = "") {
  return priority.toLowerCase();
}

function calculateThreat(network, previous, isNew) {
  let score = Number(network?.riskScore || 0);
  const reasons = [];

  const security = securityClass(network?.security);

  if (security === "open") {
    score += 15;
    reasons.push("Open network");
  }

  if (security === "wep") {
    score += 20;
    reasons.push("Weak WEP security");
  }

  if (Number(network?.rssi) >= -40) {
    score += 10;
    reasons.push("Very strong signal");
  }

  if (isNew) {
    score += 20;
    reasons.push("Newly detected");
  }

  if (previous) {
    const rssiChange = Math.abs(
      Number(network?.rssi || 0) -
        Number(previous?.rssi || 0)
    );

    if (rssiChange >= 15) {
      score += 15;
      reasons.push(`RSSI changed ${rssiChange} dBm`);
    }

    if (
      previous.channel &&
      network.channel &&
      Number(previous.channel) !== Number(network.channel)
    ) {
      score += 10;
      reasons.push(
        `Channel changed ${previous.channel} → ${network.channel}`
      );
    }
  }

  score = Math.min(score, 100);

  let priority = "LOW";

  if (score >= 80) priority = "CRITICAL";
  else if (score >= 60) priority = "HIGH";
  else if (score >= 35) priority = "MEDIUM";

  if (!reasons.length) {
    reasons.push("No significant suspicious indicators");
  }

  return {
    score,
    priority,
    reasons,
  };
}

function calculateEnvironmentThreat(networks) {
  if (!networks.length) {
    return {
      score: 0,
      level: "LOW",
      explanation: "No networks detected",
    };
  }

  const average =
    networks.reduce(
      (sum, network) =>
        sum + Number(network.threatScore || 0),
      0
    ) / networks.length;

  const highPriority = networks.filter(
    (network) =>
      network.threatPriority === "HIGH" ||
      network.threatPriority === "CRITICAL"
  ).length;

  const openNetworks = networks.filter(
    (network) =>
      securityClass(network.security) === "open"
  ).length;

  const newNetworks = networks.filter(
    (network) => network.isNew
  ).length;

  let score = average;

  if (highPriority >= 1) score += 10;
  if (highPriority >= 3) score += 10;
  if (openNetworks >= 2) score += 5;
  if (newNetworks >= 2) score += 5;

  score = Math.min(Math.round(score), 100);

  let level = "LOW";

  if (score >= 75) level = "CRITICAL";
  else if (score >= 50) level = "HIGH";
  else if (score >= 25) level = "MEDIUM";

  let explanation =
    "Environment appears relatively stable";

  if (level === "MEDIUM") {
    explanation =
      "Some security concerns require monitoring";
  }

  if (level === "HIGH") {
    explanation =
      "Several suspicious network indicators detected";
  }

  if (level === "CRITICAL") {
    explanation =
      "Multiple high-risk indicators require immediate review";
  }

  return {
    score,
    level,
    explanation,
  };
}

function App() {
  const [networks, setNetworks] = useState([]);
  const [online, setOnline] = useState(false);
  const [lastScan, setLastScan] = useState(null);
  const [scannerBusy, setScannerBusy] = useState(false);

  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [priorityFilter, setPriorityFilter] =
    useState("ALL");
  const [sortBy, setSortBy] = useState("THREAT");

  const [history, setHistory] = useState(loadHistory());
  const [events, setEvents] = useState([]);
  const [rssiHistory, setRssiHistory] = useState([]);

  const previousNetworksRef = useRef([]);

  const addEvent = (event) => {
    setEvents((current) => [
      {
        ...event,
        timestamp: Date.now(),
      },
      ...current,
    ].slice(0, 50));
  };

  const saveSnapshot = (data) => {
    const snapshot = {
      timestamp: Date.now(),
      networkCount: data.length,

      highRisk: data.filter(
        (n) =>
          n.threatPriority === "HIGH" ||
          n.threatPriority === "CRITICAL"
      ).length,

      mediumRisk: data.filter(
        (n) => n.threatPriority === "MEDIUM"
      ).length,

      openNetworks: data.filter(
        (n) => securityClass(n.security) === "open"
      ).length,

      securedNetworks: data.filter(
        (n) => securityClass(n.security) !== "open"
      ).length,

      averageRssi: data.length
        ? Math.round(
            data.reduce(
              (sum, n) => sum + Number(n.rssi || 0),
              0
            ) / data.length
          )
        : 0,

      threatScore: data.length
        ? Math.round(
            data.reduce(
              (sum, n) =>
                sum + Number(n.threatScore || 0),
              0
            ) / data.length
          )
        : 0,
    };

    setHistory((current) => {
      const updated = [...current, snapshot].slice(
        -MAX_HISTORY
      );

      localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(updated)
      );

      return updated;
    });
  };

  const processNetworks = (rawNetworks) => {
    const previous = previousNetworksRef.current;

    const processed = rawNetworks.map((network) => {
      const oldNetwork = previous.find(
        (item) =>
          item.bssid &&
          network.bssid &&
          item.bssid.toLowerCase() ===
            network.bssid.toLowerCase()
      );

      const isNew =
        previous.length > 0 && !oldNetwork;

      const threat = calculateThreat(
        network,
        oldNetwork,
        isNew
      );

      return {
        ...network,
        isNew,
        threatScore: threat.score,
        threatPriority: threat.priority,
        threatReasons: threat.reasons,
      };
    });

    if (previous.length > 0) {
      processed.forEach((network) => {
        const oldNetwork = previous.find(
          (item) =>
            item.bssid?.toLowerCase() ===
            network.bssid?.toLowerCase()
        );

        if (!oldNetwork && network.isNew) {
          addEvent({
            type: "NEW NETWORK",
            priority: network.threatPriority,
            message: `New network detected: ${
              network.ssid || "(Hidden SSID)"
            }`,
          });
        }

        if (oldNetwork) {
          const change = Math.abs(
            Number(network.rssi || 0) -
              Number(oldNetwork.rssi || 0)
          );

          if (change >= 15) {
            addEvent({
              type: "RSSI ANOMALY",
              priority: "MEDIUM",
              message: `${
                network.ssid || "(Hidden SSID)"
              } changed by ${change} dBm`,
            });
          }
        }
      });
    }

    previousNetworksRef.current = processed;

    return processed;
  };

  const fetchData = async (manual = false) => {
    try {
      if (manual) {
        setScannerBusy(true);

        await fetch(`${API_BASE}/api/scan`, {
          cache: "no-store",
        });
      }

      const response = await fetch(
        `${API_BASE}/api/data`,
        {
          cache: "no-store",
        }
      );

      if (!response.ok) {
        throw new Error("ESP32 API error");
      }

      const data = await response.json();

      const rawNetworks = Array.isArray(data.networks)
        ? data.networks
        : [];

      const processed = processNetworks(rawNetworks);

      setNetworks(processed);
      setOnline(true);
      setLastScan(Date.now());

      saveSnapshot(processed);

      const tracked = processed.find(
        (network) =>
          String(network.ssid).toLowerCase() ===
          TRACKED_SSID.toLowerCase()
      );

      if (tracked) {
        setRssiHistory((current) =>
          [
            ...current,
            {
              timestamp: Date.now(),
              rssi: Number(tracked.rssi),
            },
          ].slice(-30)
        );
      }
    } catch (error) {
      console.error(error);
      setOnline(false);
    } finally {
      setScannerBusy(false);
    }
  };

  useEffect(() => {
    fetchData();

    const interval = setInterval(
      () => fetchData(),
      5000
    );

    return () => clearInterval(interval);
  }, []);

  const threat = useMemo(
    () => calculateEnvironmentThreat(networks),
    [networks]
  );

  const stats = useMemo(() => {
    const critical = networks.filter(
      (n) => n.threatPriority === "CRITICAL"
    ).length;

    const high = networks.filter(
      (n) => n.threatPriority === "HIGH"
    ).length;

    const medium = networks.filter(
      (n) => n.threatPriority === "MEDIUM"
    ).length;

    const open = networks.filter(
      (n) => securityClass(n.security) === "open"
    ).length;

    return {
      critical,
      high,
      medium,
      open,
      secured: networks.length - open,
    };
  }, [networks]);

  const filteredNetworks = useMemo(() => {
    let result = networks.filter((network) => {
      const query = search.toLowerCase();

      const matchesSearch =
        !query ||
        String(network.ssid || "")
          .toLowerCase()
          .includes(query) ||
        String(network.bssid || "")
          .toLowerCase()
          .includes(query);

      const matchesRisk =
        riskFilter === "ALL" ||
        String(network.riskLevel || "").toUpperCase() ===
          riskFilter;

      const matchesPriority =
        priorityFilter === "ALL" ||
        network.threatPriority === priorityFilter;

      return (
        matchesSearch &&
        matchesRisk &&
        matchesPriority
      );
    });

    result = [...result].sort((a, b) => {
      if (sortBy === "THREAT") {
        return (
          Number(b.threatScore || 0) -
          Number(a.threatScore || 0)
        );
      }

      if (sortBy === "RSSI") {
        return (
          Number(b.rssi || -100) -
          Number(a.rssi || -100)
        );
      }

      if (sortBy === "SSID") {
        return String(a.ssid || "").localeCompare(
          String(b.ssid || "")
        );
      }

      if (sortBy === "CHANNEL") {
        return (
          Number(a.channel || 0) -
          Number(b.channel || 0)
        );
      }

      return 0;
    });

    return result;
  }, [
    networks,
    search,
    riskFilter,
    priorityFilter,
    sortBy,
  ]);

  const topThreats = useMemo(
    () =>
      [...networks]
        .sort(
          (a, b) =>
            Number(b.threatScore || 0) -
            Number(a.threatScore || 0)
        )
        .slice(0, 5),
    [networks]
  );

  const incidentSummary = useMemo(() => {
    const incidents = [];

    networks.forEach((network) => {
      if (
        network.threatPriority === "CRITICAL" ||
        network.threatPriority === "HIGH"
      ) {
        incidents.push({
          ssid:
            network.ssid || "(Hidden SSID)",
          bssid: network.bssid || "--",
          priority: network.threatPriority,
          score: network.threatScore,
          reasons: network.threatReasons || [],
        });
      }
    });

    return incidents.sort(
      (a, b) => b.score - a.score
    );
  }, [networks]);

  const averageThreat = useMemo(() => {
    if (!networks.length) return 0;

    return Math.round(
      networks.reduce(
        (sum, n) => sum + Number(n.threatScore || 0),
        0
      ) / networks.length
    );
  }, [networks]);

  const averageRssi = useMemo(() => {
    if (!networks.length) return 0;

    return Math.round(
      networks.reduce(
        (sum, n) => sum + Number(n.rssi || 0),
        0
      ) / networks.length
    );
  }, [networks]);

  const peakThreat = history.length
    ? Math.max(
        ...history.map(
          (item) => Number(item.threatScore) || 0
        )
      )
    : 0;

  const peakNetworks = history.length
    ? Math.max(
        ...history.map(
          (item) => Number(item.networkCount) || 0
        )
      )
    : 0;

  const clearHistory = () => {
    localStorage.removeItem(HISTORY_KEY);
    setHistory([]);
  };

  const exportReport = () => {
    const lines = [];

    lines.push(
      "================================================"
    );
    lines.push("ESP32 SECURITY MONITOR - V11");
    lines.push("SECURITY INCIDENT REPORT");
    lines.push(
      "================================================"
    );
    lines.push("");

    lines.push(`Generated: ${formatDate(Date.now())}`);
    lines.push(`ESP32 Status: ${online ? "ONLINE" : "OFFLINE"}`);
    lines.push(`API: ${API_BASE}`);
    lines.push("");

    lines.push("ENVIRONMENT");
    lines.push("-----------------------------------------------");
    lines.push(`Threat Score: ${threat.score}/100`);
    lines.push(`Threat Level: ${threat.level}`);
    lines.push(`Networks: ${networks.length}`);
    lines.push(`Average Threat: ${averageThreat}`);
    lines.push(`Average RSSI: ${averageRssi} dBm`);
    lines.push(`Open Networks: ${stats.open}`);
    lines.push(`Secured Networks: ${stats.secured}`);
    lines.push(`Critical Alerts: ${stats.critical}`);
    lines.push(`High Alerts: ${stats.high}`);
    lines.push(`Medium Alerts: ${stats.medium}`);
    lines.push("");

    lines.push("TOP THREATS");
    lines.push("-----------------------------------------------");

    if (!topThreats.length) {
      lines.push("No threats detected.");
    } else {
      topThreats.forEach((network, index) => {
        lines.push(
          `${index + 1}. ${
            network.ssid || "(Hidden SSID)"
          }`
        );
        lines.push(`   BSSID: ${network.bssid || "--"}`);
        lines.push(`   RSSI: ${network.rssi} dBm`);
        lines.push(`   Channel: ${network.channel || "--"}`);
        lines.push(
          `   Security: ${network.security || "UNKNOWN"}`
        );
        lines.push(
          `   Threat Score: ${network.threatScore}`
        );
        lines.push(
          `   Priority: ${network.threatPriority}`
        );
        lines.push(
          `   Reasons: ${
            network.threatReasons?.join(", ") || "None"
          }`
        );
        lines.push("");
      });
    }

    lines.push("SECURITY INCIDENTS");
    lines.push("-----------------------------------------------");

    if (!incidentSummary.length) {
      lines.push("No HIGH or CRITICAL incidents.");
    } else {
      incidentSummary.forEach((incident, index) => {
        lines.push(
          `${index + 1}. ${incident.ssid}`
        );
        lines.push(`   BSSID: ${incident.bssid}`);
        lines.push(
          `   Priority: ${incident.priority}`
        );
        lines.push(`   Score: ${incident.score}`);
        lines.push(
          `   Reasons: ${incident.reasons.join(", ")}`
        );
        lines.push("");
      });
    }

    lines.push("HISTORICAL ANALYTICS");
    lines.push("-----------------------------------------------");
    lines.push(`Samples Stored: ${history.length}`);
    lines.push(`Peak Threat: ${peakThreat}`);
    lines.push(`Peak Networks: ${peakNetworks}`);
    lines.push("");

    lines.push("TRACKED NETWORK");
    lines.push("-----------------------------------------------");
    lines.push(`SSID: ${TRACKED_SSID}`);

    const tracked = networks.find(
      (n) =>
        String(n.ssid).toLowerCase() ===
        TRACKED_SSID.toLowerCase()
    );

    if (tracked) {
      lines.push(`Current RSSI: ${tracked.rssi} dBm`);
      lines.push(
        `Security: ${tracked.security || "UNKNOWN"}`
      );
      lines.push(
        `Threat Score: ${tracked.threatScore}`
      );
      lines.push(
        `Priority: ${tracked.threatPriority}`
      );
    } else {
      lines.push("Network not currently detected.");
    }

    lines.push("");
    lines.push(
      "================================================"
    );
    lines.push("Generated by ESP32 Security Monitor V11");
    lines.push(
      "================================================"
    );

    const blob = new Blob([lines.join("\n")], {
      type: "text/plain",
    });

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = `ESP32-Security-Report-${Date.now()}.txt`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">◈</div>

          <div>
            <div className="brand-title">
              ESP32 SECURITY MONITOR
            </div>

            <div className="brand-subtitle">
              V11 • SOC THREAT INTELLIGENCE
            </div>
          </div>
        </div>

        <div className="connection-box">
          <span
            className={`connection-dot ${
              online ? "online" : "offline"
            }`}
          />

          <span>
            {online ? "ESP32 ONLINE" : "ESP32 OFFLINE"}
          </span>

          <span className="connection-ip">
            192.168.4.1
          </span>
        </div>
      </header>

      <main className="container">
        <section className="threat-hero">
          <div className="threat-main">
            <div className="section-label">
              ENVIRONMENT THREAT SCORE
            </div>

            <div className="threat-score-row">
              <div className="big-threat-score">
                {threat.score}
              </div>

              <div
                className={`threat-level ${threat.level.toLowerCase()}`}
              >
                {threat.level}
              </div>
            </div>

            <div className="threat-explanation">
              {threat.explanation}
            </div>

            <div className="threat-meter">
              <div
                className={`threat-meter-fill ${threat.level.toLowerCase()}`}
                style={{
                  width: `${threat.score}%`,
                }}
              />
            </div>
          </div>

          <div className="threat-summary">
            <div className="mini-stat">
              <span>CRITICAL</span>
              <strong>{stats.critical}</strong>
            </div>

            <div className="mini-stat">
              <span>HIGH</span>
              <strong>{stats.high}</strong>
            </div>

            <div className="mini-stat">
              <span>OPEN WIFI</span>
              <strong>{stats.open}</strong>
            </div>

            <div className="mini-stat">
              <span>INCIDENTS</span>
              <strong>{incidentSummary.length}</strong>
            </div>
          </div>
        </section>

        <section className="stats-grid">
          <div className="stat-card">
            <span>NETWORKS</span>
            <strong>{networks.length}</strong>
            <small>Current scan</small>
          </div>

          <div className="stat-card danger">
            <span>CRITICAL</span>
            <strong>{stats.critical}</strong>
            <small>Immediate review</small>
          </div>

          <div className="stat-card danger">
            <span>HIGH</span>
            <strong>{stats.high}</strong>
            <small>Requires attention</small>
          </div>

          <div className="stat-card warning">
            <span>MEDIUM</span>
            <strong>{stats.medium}</strong>
            <small>Monitor</small>
          </div>

          <div className="stat-card">
            <span>SECURED</span>
            <strong>{stats.secured}</strong>
            <small>Protected networks</small>
          </div>
        </section>

        <section className="soc-action-bar">
          <div>
            <strong>SOC ACTION CENTER</strong>
            <span>
              Generate a local security report from the
              current monitoring session.
            </span>
          </div>

          <button
            className="export-button"
            onClick={exportReport}
          >
            EXPORT SECURITY REPORT
          </button>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                SECURITY INCIDENT SUMMARY
              </div>

              <div className="panel-subtitle">
                HIGH and CRITICAL observations requiring
                analyst attention
              </div>
            </div>

            <div className="incident-counter">
              {incidentSummary.length} INCIDENTS
            </div>
          </div>

          <div className="incident-grid">
            {incidentSummary.length === 0 ? (
              <div className="empty-state">
                No HIGH or CRITICAL incidents detected.
              </div>
            ) : (
              incidentSummary.map((incident, index) => (
                <div
                  className="incident-card"
                  key={`${incident.bssid}-${index}`}
                >
                  <div className="incident-top">
                    <span className="incident-number">
                      INC-{String(index + 1).padStart(3, "0")}
                    </span>

                    <span
                      className={`priority-badge ${priorityClass(
                        incident.priority
                      )}`}
                    >
                      {incident.priority}
                    </span>
                  </div>

                  <strong className="incident-ssid">
                    {incident.ssid}
                  </strong>

                  <span className="incident-bssid">
                    {incident.bssid}
                  </span>

                  <div className="incident-score">
                    <span>THREAT SCORE</span>
                    <strong>{incident.score}/100</strong>
                  </div>

                  <div className="incident-reasons">
                    {incident.reasons.map(
                      (reason, reasonIndex) => (
                        <span key={reasonIndex}>
                          • {reason}
                        </span>
                      )
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                THREAT INTELLIGENCE
              </div>

              <div className="panel-subtitle">
                Highest priority observations
              </div>
            </div>
          </div>

          <div className="threat-list">
            {topThreats.length === 0 ? (
              <div className="empty-state">
                No networks detected.
              </div>
            ) : (
              topThreats.map((network, index) => (
                <div
                  className="threat-item"
                  key={`${network.bssid}-${index}`}
                >
                  <div className="threat-rank">
                    #{index + 1}
                  </div>

                  <div className="threat-network">
                    <strong>
                      {network.ssid ||
                        "(Hidden SSID)"}
                    </strong>

                    <span>{network.bssid}</span>
                  </div>

                  <div className="threat-reasons">
                    {network.threatReasons
                      ?.slice(0, 3)
                      .map((reason, i) => (
                        <span key={i}>{reason}</span>
                      ))}
                  </div>

                  <span
                    className={`priority-badge ${priorityClass(
                      network.threatPriority
                    )}`}
                  >
                    {network.threatPriority}
                  </span>

                  <div className="threat-number">
                    {network.threatScore}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="scanner-bar">
          <div>
            <div className="scanner-title">
              PASSIVE WI-FI SCANNER
            </div>

            <div className="scanner-subtitle">
              Last scan:{" "}
              {lastScan ? formatTime(lastScan) : "--"}
            </div>
          </div>

          <button
            className="scan-button"
            disabled={scannerBusy}
            onClick={() => fetchData(true)}
          >
            {scannerBusy ? "SCANNING..." : "SCAN NOW"}
          </button>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                LIVE NETWORK INTELLIGENCE
              </div>

              <div className="panel-subtitle">
                Search • Filter • Sort
              </div>
            </div>

            <div className="network-count">
              {filteredNetworks.length} /{" "}
              {networks.length}
            </div>
          </div>

          <div className="network-controls">
            <input
              className="search-input"
              placeholder="Search SSID or BSSID..."
              value={search}
              onChange={(e) =>
                setSearch(e.target.value)
              }
            />

            <select
              value={riskFilter}
              onChange={(e) =>
                setRiskFilter(e.target.value)
              }
            >
              <option value="ALL">All Risk</option>
              <option value="HIGH">High Risk</option>
              <option value="MEDIUM">Medium Risk</option>
              <option value="LOW">Low Risk</option>
            </select>

            <select
              value={priorityFilter}
              onChange={(e) =>
                setPriorityFilter(e.target.value)
              }
            >
              <option value="ALL">
                All Priority
              </option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={sortBy}
              onChange={(e) =>
                setSortBy(e.target.value)
              }
            >
              <option value="THREAT">
                Sort: Threat
              </option>
              <option value="RSSI">Sort: RSSI</option>
              <option value="SSID">Sort: SSID</option>
              <option value="CHANNEL">
                Sort: Channel
              </option>
            </select>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>SSID</th>
                  <th>BSSID</th>
                  <th>RSSI</th>
                  <th>CH</th>
                  <th>SECURITY</th>
                  <th>RISK</th>
                  <th>THREAT</th>
                  <th>PRIORITY</th>
                </tr>
              </thead>

              <tbody>
                {filteredNetworks.map(
                  (network, index) => (
                    <tr
                      key={`${network.bssid}-${index}`}
                    >
                      <td>
                        <div className="ssid-cell">
                          <strong>
                            {network.ssid ||
                              "(Hidden SSID)"}
                          </strong>

                          {network.isNew && (
                            <span className="new-tag">
                              NEW
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="mono">
                        {network.bssid || "--"}
                      </td>

                      <td className="rssi-value">
                        {network.rssi} dBm
                      </td>

                      <td>
                        {network.channel || "--"}
                      </td>

                      <td>
                        <span
                          className={`security-badge ${securityClass(
                            network.security
                          )}`}
                        >
                          {network.security ||
                            "UNKNOWN"}
                        </span>
                      </td>

                      <td>
                        <span
                          className={`risk-badge ${String(
                            network.riskLevel ||
                              "LOW"
                          ).toLowerCase()}`}
                        >
                          {network.riskLevel ||
                            "LOW"}
                        </span>
                      </td>

                      <td>
                        <div className="threat-cell">
                          <strong>
                            {network.threatScore}
                          </strong>

                          <div className="mini-threat-bar">
                            <span
                              style={{
                                width: `${network.threatScore}%`,
                              }}
                            />
                          </div>
                        </div>
                      </td>

                      <td>
                        <span
                          className={`priority-badge ${priorityClass(
                            network.threatPriority
                          )}`}
                        >
                          {network.threatPriority}
                        </span>
                      </td>
                    </tr>
                  )
                )}
              </tbody>
            </table>

            {!filteredNetworks.length && (
              <div className="empty-state">
                No networks match your filters.
              </div>
            )}
          </div>
        </section>

        <div className="two-column">
          <section className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">
                  TRACKED RSSI
                </div>

                <div className="panel-subtitle">
                  {TRACKED_SSID}
                </div>
              </div>
            </div>

            <div className="rssi-panel">
              <div className="rssi-current">
                <span>CURRENT</span>

                <strong>
                  {(() => {
                    const tracked = networks.find(
                      (n) =>
                        String(n.ssid).toLowerCase() ===
                        TRACKED_SSID.toLowerCase()
                    );

                    return tracked
                      ? `${tracked.rssi} dBm`
                      : "--";
                  })()}
                </strong>
              </div>

              <div className="rssi-bars">
                {rssiHistory.length === 0 ? (
                  <div className="empty-state">
                    Waiting for tracked network...
                  </div>
                ) : (
                  rssiHistory.map(
                    (point, index) => {
                      const height = Math.max(
                        5,
                        Math.min(
                          100,
                          ((point.rssi + 100) /
                            70) *
                            100
                        )
                      );

                      return (
                        <div
                          className="rssi-bar"
                          key={`${point.timestamp}-${index}`}
                          title={`${point.rssi} dBm`}
                        >
                          <span
                            style={{
                              height: `${height}%`,
                            }}
                          />
                        </div>
                      );
                    }
                  )
                )}
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">
                  SOC ALERT STREAM
                </div>

                <div className="panel-subtitle">
                  Latest monitoring events
                </div>
              </div>
            </div>

            <div className="event-list">
              {events.length === 0 ? (
                <div className="empty-state">
                  No security events yet.
                </div>
              ) : (
                events.slice(0, 8).map(
                  (event, index) => (
                    <div
                      className="event-item"
                      key={index}
                    >
                      <div
                        className={`event-dot ${priorityClass(
                          event.priority
                        )}`}
                      />

                      <div className="event-content">
                        <strong>
                          {event.type}
                        </strong>

                        <span>
                          {event.message}
                        </span>

                        <small>
                          {formatTime(
                            event.timestamp
                          )}
                        </small>
                      </div>

                      <span
                        className={`priority-badge ${priorityClass(
                          event.priority
                        )}`}
                      >
                        {event.priority}
                      </span>
                    </div>
                  )
                )
              )}
            </div>
          </section>
        </div>

        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                HISTORICAL SECURITY ANALYTICS
              </div>

              <div className="panel-subtitle">
                Local browser history
              </div>
            </div>

            <button
              className="clear-button"
              onClick={clearHistory}
            >
              CLEAR HISTORY
            </button>
          </div>

          <div className="history-chart">
            {history.length === 0 ? (
              <div className="empty-state">
                Historical data will appear after scans.
              </div>
            ) : (
              history.map((item, index) => (
                <div
                  className="history-point"
                  key={`${item.timestamp}-${index}`}
                  title={`Threat ${item.threatScore} • ${item.networkCount} networks`}
                >
                  <div
                    className="history-bar"
                    style={{
                      height: `${Math.max(
                        5,
                        item.threatScore || 0
                      )}%`,
                    }}
                  />
                </div>
              ))
            )}
          </div>

          <div className="history-summary">
            <div>
              <span>SAMPLES</span>
              <strong>{history.length}</strong>
            </div>

            <div>
              <span>PEAK THREAT</span>
              <strong>{peakThreat}</strong>
            </div>

            <div>
              <span>PEAK NETWORKS</span>
              <strong>{peakNetworks}</strong>
            </div>

            <div>
              <span>LAST THREAT</span>
              <strong>
                {history.length
                  ? history[history.length - 1]
                      .threatScore
                  : 0}
              </strong>
            </div>
          </div>
        </section>

        <footer className="footer">
          <span>
            ESP32 SECURITY MONITOR • V11 FINAL
          </span>

          <span>
            Passive monitoring • Local threat analysis •
            SOC reporting
          </span>
        </footer>
      </main>
    </div>
  );
}

export default App;