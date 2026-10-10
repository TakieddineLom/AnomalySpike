const API_BASE = "";

let selectedNetwork = "";

const elements = {
    apiStatus: document.getElementById("api-status"),
    statusDot: document.getElementById("status-dot"),
    networkSelector: document.getElementById("network-selector"),

    eventsCount: document.getElementById("events-count"),
    anomaliesCount: document.getElementById("anomalies-count"),
    hostsCount: document.getElementById("hosts-count"),

    anomaliesTable: document.getElementById("anomalies-table"),
    alertsTable: document.getElementById("alerts-table"),
    eventsTable: document.getElementById("events-table"),

    refreshButton: document.getElementById("refresh-btn"),

    modal: document.getElementById("anomaly-modal"),
    modalTitle: document.getElementById("modal-title"),
    modalSubtitle: document.getElementById("modal-subtitle"),
    modalContent: document.getElementById("anomaly-details"),
    modalClose: document.getElementById("modal-close")
};

if (elements.networkSelector) {
    elements.networkSelector.addEventListener("change", async () => {
const selectedInterface = elements.networkSelector.value;

    try {
        await apiRequest(
            `/api/interfaces/select?interface=${encodeURIComponent(selectedInterface)}`,
            {
                method: "POST"
            }
        );

        console.log("Selected interface:", selectedInterface);

        loadDashboard();

    } catch (error) {
        console.error("Failed to select interface:", error);
    }
});
}


// --------------------------------------------------
// API
// --------------------------------------------------
async function loadSelectedInterface() {
    try {
        const result = await apiRequest("/api/interfaces/selected");

        if (result.interface) {
            if (elements.networkSelector) {
                elements.networkSelector.value = result.interface;
            }
            selectedNetwork = result.interface;
        }

    } catch (error) {
        console.error("Failed to load selected interface:", error);
    }
}


async function apiRequest(endpoint) {

    const response = await fetch(`${API_BASE}${endpoint}`);

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
}


// --------------------------------------------------
// Helpers
// --------------------------------------------------

function formatTime(timestamp) {

    if (!timestamp) {
        return "—";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleString();
}


function escapeHtml(value) {

    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function getData(item) {
    return item?.data || item || {};
}


function getHost(anomaly) {

    const data = getData(anomaly);

    return (
        data.source_ip ||
        data.host ||
        data.ip ||
        data.source?.ip ||
        "Unknown"
    );
}


function getTimestamp(anomaly) {

    const data = getData(anomaly);

    return (
        data["@timestamp"] ||
        data.timestamp ||
        "Unknown"
    );
}

function getScore(anomaly) {

    const data = getData(anomaly);
    const anomalyData = data.anomaly || {};
    const detection = data.detection || {};

    let score;

    if (detection.ml_anomaly) {
        score = anomalyData.ml_score;
    } else if (detection.behavioral_anomaly) {
        score = anomalyData.behavioral_score;
    } else {
        score = anomalyData.ml_score ?? anomalyData.behavioral_score;
    }

    if (score === undefined || score === null) {
        return "—";
    }

    if (typeof score === "number") {
        return score.toFixed(4);
    }

    return score;
}

function getAnomalyType(anomaly) {
    const data = getData(anomaly);
    const detection = data.detection || {};

    const behavioral =
        detection.behavioral_anomaly === true;

    const ml =
        detection.ml_anomaly === true;

    if (behavioral && ml) {
        return {
            text: "HYBRID",
            className: "badge-hybrid"
        };
    }

    if (behavioral) {
        return {
            text: "BEHAVIORAL",
            className: "badge-behavioral"
        };
    }

    if (ml) {
        return {
            text: "ML",
            className: "badge-ml"
        };
    }

    return {
        text: "ANOMALY",
        className: "badge-anomaly"
    };
}


// --------------------------------------------------
// Statistics
// --------------------------------------------------

function renderStats(stats) {

    console.log("API stats:", stats);

    elements.eventsCount.textContent =
        Number(stats?.events ?? 0).toLocaleString();

    elements.anomaliesCount.textContent =
        Number(stats?.anomalies ?? 0).toLocaleString();

    elements.hostsCount.textContent =
        Number(stats?.hosts ?? 0).toLocaleString();
}


// --------------------------------------------------
// Anomalies
// --------------------------------------------------

function renderAnomalies(anomalies) {

    if (!anomalies || anomalies.length === 0) {

        elements.anomaliesTable.innerHTML = `
            <tr>
                <td colspan="5" class="loading anomaly-empty">
                    <div class="empty-state">
                        <div class="empty-state-icon">✓</div>
                        <div class="empty-state-title">No anomalies detected</div>
                        <div class="empty-state-text">
                            No suspicious behavioral or ML signals have been detected.
                        </div>
                    </div>
                </td>
            </tr>
        `;

        return;
    }

    elements.anomaliesTable.innerHTML =
        anomalies.map((anomaly, index) => {

            const type = getAnomalyType(anomaly);
            const host = getHost(anomaly);
            const timestamp = getTimestamp(anomaly);
            const score = getScore(anomaly);

            const data = getData(anomaly);
            const detection = data.detection || {};

            const behavioral = detection.behavioral_anomaly === true;
            const ml = detection.ml_anomaly === true;

            let severityLabel = "DETECTED";
            let severityClass = "status-detected";

            if (behavioral && ml) {
                severityLabel = "HIGH";
                severityClass = "status-high";
            } else if (behavioral || ml) {
                severityLabel = "MEDIUM";
                severityClass = "status-medium";
            }

            return `
                <tr
                    class="anomaly-row ${severityClass}"
                    data-anomaly-index="${index}"
                    title="Click to investigate this anomaly"
                >

                    <td>
                        <div class="anomaly-host">
                            <span class="anomaly-host-indicator"></span>
                            <span class="ip">
                                ${escapeHtml(host)}
                            </span>
                        </div>
                    </td>

                    <td class="time">
                        ${escapeHtml(formatTime(timestamp))}
                    </td>

                    <td>
                        <span class="badge ${type.className}">
                            ${type.text}
                        </span>
                    </td>

                    <td>
                        <span class="anomaly-score">
                            ${escapeHtml(score)}
                        </span>
                    </td>

                    <td>
                        <span class="anomaly-status ${severityClass}">
                            <span class="status-dot-small"></span>
                            ${severityLabel}
                        </span>
                    </td>

                </tr>
            `;

        }).join("");

    // Make every anomaly clickable
    document.querySelectorAll(".anomaly-row").forEach(row => {

        row.addEventListener("click", () => {

            const index =
                Number(row.dataset.anomalyIndex);

            openAnomalyDetails(anomalies[index]);

        });

    });
}


function renderKnowledge(results) {
    const section = document.getElementById("knowledge-section");

    if (!section) {
        return;
    }

    if (!results || results.length === 0) {
        section.innerHTML = `
            <div class="loading">
                No related security knowledge found.
            </div>
        `;
        return;
    }

    section.innerHTML = results.map(result => {
        const source = (result.source || "Unknown source")
            .replace(/\.md$/i, "");

        const content = (result.content || "")
    	.replace(/^#{1,6}\s+/gm, "")
    	.replace(/\n+/g, " ")
    	.replace(/\s+/g, " ")
    	.trim();

	let preview = content;

if (preview.length > 280) {
    preview = preview.substring(0, 280);

    const firstSpace = preview.indexOf(" ");
    if (firstSpace > 0 && firstSpace < 40) {
        preview = preview.substring(firstSpace + 1);
    }

    preview = preview.trim() + "...";
}

        return `
            <div class="knowledge-item">
                <div class="knowledge-header">
                    <strong>${source}</strong>
                    <span class="knowledge-score">
                        Relevance: ${Number(result.score || 0).toFixed(4)}
                    </span>
                </div>

                <div class="knowledge-content">
                    ${preview}
                </div>
            </div>
        `;
    }).join("");
}

// --------------------------------------------------
// Anomaly investigation
// --------------------------------------------------

async function openAnomalyDetails(anomaly) {

    elements.modalTitle.textContent =
        "Anomaly Investigation";

    elements.modalSubtitle.textContent =
        "Host activity and detection evidence";

    const data = getData(anomaly);

    const host = getHost(anomaly);

    const timestamp = getTimestamp(anomaly);

    const type = getAnomalyType(anomaly);

    elements.modalContent.innerHTML = `
        <div class="detail-grid">

            <div class="detail-item">
                <span>HOST</span>
                <strong class="ip">
                    ${escapeHtml(host)}
                </strong>
            </div>

            <div class="detail-item">
                <span>TIME</span>
                <strong>
                    ${escapeHtml(formatTime(timestamp))}
                </strong>
            </div>

            <div class="detail-item">
                <span>DETECTION</span>
                <strong>
                    <span class="badge ${type.className}">
                        ${type.text}
                    </span>
                </strong>
            </div>

            <div class="detail-item">
                <span>SCORE</span>
                <strong>
                    ${escapeHtml(getScore(anomaly))}
                </strong>
            </div>

        </div>

        <h3>Detection Evidence</h3>

        <div id="evidence-section" class="evidence-section">
            ${renderEvidence(data)}
        </div>

        <h3>Related Security Knowledge</h3>

        <div id="knowledge-section" class="evidence-section">
            <div class="loading">
                Searching knowledge base...
            </div>
        </div>

        <h3>Host Timeline</h3>

        <div id="timeline-section" class="timeline-section">
            <div class="loading">
                Loading host timeline...
            </div>
        </div>
    `;


    elements.modal.classList.add("visible");


    // Load related security knowledge based on the detection type
    try {

        const query = `${type.text} anomaly detection ${host}`;

        const knowledgeResult =
            await apiRequest(
                `/api/knowledge/search?q=${encodeURIComponent(query)}&top_k=2`
            );

        renderKnowledge(
            knowledgeResult.results || []
        );

    } catch (error) {
        console.error("Failed to load security knowledge:", error);

        const knowledgeSection = document.getElementById("knowledge-section");
        if (knowledgeSection) {
            knowledgeSection.innerHTML =
                `<div class="loading">Unable to load security knowledge.</div>`;
        }
    }


    // Load the actual host timeline from FastAPI
    try {

        const result =
            await apiRequest(
                `/api/hosts/${encodeURIComponent(host)}/timeline?size=20`
            );

        renderTimeline(
            result.events || []
        );


    } catch (error) {

        console.error(
            "Timeline error:",
            error
        );

        const timeline =
            document.getElementById(
                "timeline-section"
            );

        if (timeline) {

            timeline.innerHTML = `
                <div class="error-message">
                    Unable to load host timeline.
                </div>
            `;
        }
    }
}

function renderEvidence(data) {
    const features = data.features || {};
    const anomaly = data.anomaly || {};
    const detection = data.detection || {};

    const featureFields = [
        ["Connections", features.connection_count],
        ["DNS Queries", features.dns_query_count],
        ["Unique Destinations", features.unique_destination_count],
        ["Bytes Sent", features.bytes_sent],
        ["Bytes Received", features.bytes_received],
        ["Failed Connections", features.failed_connection_count]
    ];

    const available = featureFields.filter(
        ([, value]) =>
            value !== undefined &&
            value !== null
    );

    let html = "";

    // -----------------------------
    // Network features
    // -----------------------------

    if (available.length > 0) {
        html += `
            <div class="evidence-grid">
                ${available.map(([label, value]) => `
                    <div class="evidence-card">
                        <span>${escapeHtml(label)}</span>
                        <strong>${escapeHtml(
                            Number(value).toLocaleString()
                        )}</strong>
                    </div>
                `).join("")}
            </div>
        `;
    }

    // -----------------------------
    // Detection status
    // -----------------------------

    html += `
        <div class="detection-summary">

            <div class="detection-item">
                <span>Behavioral Detection</span>
                <strong class="${detection.behavioral_anomaly ? "danger" : "normal"}">
                    ${detection.behavioral_anomaly ? "ANOMALY" : "NORMAL"}
                </strong>
            </div>

            <div class="detection-item">
                <span>ML Detection</span>
                <strong class="${detection.ml_anomaly ? "danger" : "normal"}">
                    ${detection.ml_anomaly ? "ANOMALY" : "NORMAL"}
                </strong>
            </div>

            <div class="detection-item">
                <span>Behavioral Score</span>
                <strong>
                    ${anomaly.behavioral_score !== undefined
                        ? Number(anomaly.behavioral_score).toFixed(4)
                        : "—"}
                </strong>
            </div>

            <div class="detection-item">
                <span>ML Score</span>
                <strong>
                    ${anomaly.ml_score !== undefined
                        ? Number(anomaly.ml_score).toFixed(4)
                        : "—"}
                </strong>
            </div>

            <div class="detection-item">
                <span>Model</span>
                <strong>
                    ${escapeHtml(anomaly.model || "—")}
                </strong>
            </div>

            <div class="detection-item">
                <span>Version</span>
                <strong>
                    ${escapeHtml(anomaly.version || "—")}
                </strong>
            </div>

        </div>
    `;

    // -----------------------------
    // Detection evidence
    // -----------------------------

    if (
        Array.isArray(detection.evidence) &&
        detection.evidence.length > 0
    ) {
        html += `
            <div class="detection-evidence">
                <h4>Why was this detected?</h4>

                ${detection.evidence.map(item => `
                    <div class="evidence-detail">

                        <div class="evidence-detail-header">
                            <strong>
                                ${escapeHtml(
                                    item.feature || "Unknown feature"
                                )}
                            </strong>

                            <span>
                                ${escapeHtml(
                                    item.direction || ""
                                )}
                            </span>
                        </div>

                        <div class="evidence-values">

                            <div>
                                <span>Current</span>
                                <strong>
                                    ${item.current !== undefined
                                        ? Number(item.current).toLocaleString()
                                        : "—"}
                                </strong>
                            </div>

                            <div>
                                <span>Baseline Max</span>
                                <strong>
                                    ${item.baseline_max !== undefined
                                        ? Number(item.baseline_max).toLocaleString()
                                        : "—"}
                                </strong>
                            </div>

                            <div>
                                <span>Baseline Mean</span>
                                <strong>
                                    ${item.baseline_mean !== undefined
                                        ? Number(item.baseline_mean).toLocaleString()
                                        : "—"}
                                </strong>
                            </div>

                            <div>
                                <span>Ratio</span>
                                <strong>
                                    ${item.ratio_to_max !== undefined
                                        ? Number(item.ratio_to_max).toFixed(2) + "×"
                                        : "—"}
                                </strong>
                            </div>

                        </div>
                    </div>
                `).join("")}
            </div>
        `;
    }

    return html;
}


function renderTimeline(events) {

    const timeline =
        document.getElementById(
            "timeline-section"
        );

    if (!timeline) {
        return;
    }


    if (!events || events.length === 0) {

        timeline.innerHTML = `
            <div class="loading">
                No timeline events found.
            </div>
        `;

        return;
    }


    timeline.innerHTML =
        events.map(event => {

            const data =
                getData(event);

            const time =
                data["@timestamp"] ||
                data.timestamp ||
                "Unknown";

            const source =
                data.source?.ip ||
                data.source_ip ||
                "—";

            const destination =
                data.destination?.ip ||
                data.destination_ip ||
                "—";

            const service =
                data.zeek?.service ||
                data.service ||
                "—";

            return `
                <div class="timeline-event">

                    <div class="timeline-time">
                        ${escapeHtml(
                            formatTime(time)
                        )}
                    </div>

                    <div class="timeline-content">

                        <strong>
                            ${escapeHtml(source)}
                        </strong>

                        <span>
                            →
                            ${escapeHtml(destination)}
                        </span>

                        <small>
                            ${escapeHtml(service)}
                        </small>

                    </div>

                </div>
            `;

        }).join("");
}


// --------------------------------------------------
// Network events
// --------------------------------------------------

function getEventSource(event) {

    const data = getData(event);

    return (
        data.source?.ip ||
        data.src_ip ||
        data.source_ip ||
        "—"
    );
}


function getEventDestination(event) {

    const data = getData(event);

    return (
        data.destination?.ip ||
        data.dest_ip ||
        data.destination_ip ||
        "—"
    );
}


function getEventProtocol(event) {

    const data = getData(event);

    return (
        data.network?.transport ||
        data.transport ||
        data.protocol ||
        "—"
    );
}


function getEventService(event) {

    const data = getData(event);

    return (
        data.zeek?.service ||
        data.service ||
        "—"
    );
}


function getEventTimestamp(event) {

    const data = getData(event);

    return (
        data["@timestamp"] ||
        data.timestamp ||
        "—"
    );
}


function renderEvents(events) {

    if (!events || events.length === 0) {

        elements.eventsTable.innerHTML = `
            <tr>
                <td colspan="5" class="loading">
                    No network events
                </td>
            </tr>
        `;

        return;
    }


    elements.eventsTable.innerHTML =
        events.map(event => {

            return `
                <tr>

                    <td class="ip">
                        ${escapeHtml(
                            getEventSource(event)
                        )}
                    </td>

                    <td class="ip">
                        ${escapeHtml(
                            getEventDestination(event)
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            getEventProtocol(event)
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            getEventService(event)
                        )}
                    </td>

                    <td class="time">
                        ${escapeHtml(
                            formatTime(
                                getEventTimestamp(event)
                            )
                        )}
                    </td>

                </tr>
            `;

        }).join("");
}

// --------------------------------------------------
// Suricata security alerts
// --------------------------------------------------
function getAlertSeverity(severity) {

    const value = Number(severity);

    if (value === 1) {
        return {
            label: "HIGH",
            className: "danger"
        };
    }

    if (value === 2) {
        return {
            label: "MEDIUM",
            className: "warning"
        };
    }

    if (value === 3) {
        return {
            label: "LOW",
            className: "normal"
        };
    }

    return {
        label: "UNKNOWN",
        className: "normal"
    };
}
// --------------------------------------------------
// Suricata security alerts
// --------------------------------------------------

function renderAlerts(alerts) {

    if (!alerts || alerts.length === 0) {

        elements.alertsTable.innerHTML = `
            <tr>
                <td colspan="6" class="loading">
                    No security alerts
                </td>
            </tr>
        `;

        return;
    }

    elements.alertsTable.innerHTML =
        alerts.map((alert, index) => {

            const data = getData(alert);

            const source =
                data.source?.ip || "—";

            const destination =
                data.destination?.ip || "—";

            const signature =
                data.suricata?.signature || "Unknown";

            const severity =
                data.suricata?.severity ?? null;

            const severityInfo =
                getAlertSeverity(severity);

            const action =
                data.suricata?.action || "—";

            const timestamp =
                data["@timestamp"] || "—";


            return `
                <tr
                    class="alert-row"
                    data-alert-index="${index}"
                    title="Click to investigate this security alert"
                >

                    <td>
                        ${escapeHtml(signature)}
                    </td>

                    <td class="ip">
                        ${escapeHtml(source)}
                    </td>

                    <td class="ip">
                        ${escapeHtml(destination)}
                    </td>

                    <td>
                        <span class="badge ${severityInfo.className}">
                            ${escapeHtml(severityInfo.label)}
                        </span>
                    </td>

                    <td>
                        ${escapeHtml(action)}
                    </td>

                    <td class="time">
                        ${escapeHtml(
                            formatTime(timestamp)
                        )}
                    </td>

                </tr>
            `;

        }).join("");


    // Make every security alert clickable

    document.querySelectorAll(".alert-row").forEach(row => {

        row.addEventListener("click", () => {

            const index =
                Number(row.dataset.alertIndex);

            openAlertDetails(alerts[index]);

        });

    });
}

// --------------------------------------------------
// Security alert investigation
// --------------------------------------------------

function openAlertDetails(alert) {

    elements.modalTitle.textContent =
        "Security Alert Investigation";

    elements.modalSubtitle.textContent =
        "Suricata IDS detection details";

    const data = getData(alert);

    const suricata =
        data.suricata || {};

    const source =
        data.source || {};

    const destination =
        data.destination || {};

    const timestamp =
        data["@timestamp"] ||
        data.timestamp ||
        "—";

    const severity =
        data.suricata?.severity ?? null;

    const severityInfo =
        getAlertSeverity(severity);

    let severityClass = "normal";

   
    elements.modalContent.innerHTML = `

        <div class="detail-grid">

            <div class="detail-item">
                <span>SIGNATURE</span>
                <strong>
                    ${escapeHtml(
                        suricata.signature || "Unknown"
                    )}
                </strong>
            </div>

            <div class="detail-item">
                <span>SEVERITY</span>
                <strong>
                    <span class="badge ${severityInfo.className}">
                          ${escapeHtml(severityInfo.label)}
                    </span>
                </strong>
            </div>

            <div class="detail-item">
                <span>ACTION</span>
                <strong>
                    ${escapeHtml(
                        suricata.action || "—"
                    )}
                </strong>
            </div>

            <div class="detail-item">
                <span>CATEGORY</span>
                <strong>
                    ${escapeHtml(
                        suricata.category || "—"
                    )}
                </strong>
            </div>

            <div class="detail-item">
                <span>SOURCE</span>
                <strong class="ip">
                    ${escapeHtml(
                        source.ip || "—"
                    )}
                    ${source.port
                        ? ":" + escapeHtml(source.port)
                        : ""}
                </strong>
            </div>

            <div class="detail-item">
                <span>DESTINATION</span>
                <strong class="ip">
                    ${escapeHtml(
                        destination.ip || "—"
                    )}
                    ${destination.port
                        ? ":" + escapeHtml(destination.port)
                        : ""}
                </strong>
            </div>

            <div class="detail-item">
                <span>PROTOCOL</span>
                <strong>
                    ${escapeHtml(
                        suricata.protocol ||
                        data.network?.transport ||
                        "—"
                    )}
                </strong>
            </div>

            <div class="detail-item">
                <span>TIME</span>
                <strong>
                    ${escapeHtml(
                        formatTime(timestamp)
                    )}
                </strong>
            </div>

            <div class="detail-item">
                <span>SIGNATURE ID</span>
                <strong>
                    ${escapeHtml(
                        suricata.signature_id ?? "—"
                    )}
                </strong>
            </div>

            <div class="detail-item">
                <span>REVISION</span>
                <strong>
                    ${escapeHtml(
                        suricata.rev ?? "—"
                    )}
                </strong>
            </div>

        </div>

        <h3>Suricata Detection</h3>

        <div class="detection-summary">

            <div class="detection-item">
                <span>Engine</span>
                <strong>Suricata IDS</strong>
            </div>

            <div class="detection-item">
                <span>Event Type</span>
                <strong>
                    ${escapeHtml(
                        suricata.event_type || "alert"
                    )}
                </strong>
            </div>

            <div class="detection-item">
                <span>Sensor</span>
                <strong>
                    ${escapeHtml(
                        data.anomalyspike?.sensor || "—"
                    )}
                </strong>
            </div>

            <div class="detection-item">
                <span>Pipeline</span>
                <strong>
                    ${escapeHtml(
                        data.anomalyspike?.pipeline || "—"
                    )}
                </strong>
            </div>

        </div>
    `;

    elements.modal.classList.add("visible");
}

// --------------------------------------------------
// Dashboard loading

async function loadInterfaces() {
    try {
        const result = await apiRequest("/api/interfaces");

        const interfaces = result.interfaces || [];

        elements.networkSelector.innerHTML = "";

        interfaces
            .filter(iface =>
            iface.name !== "lo" &&
            !iface.name.startsWith("docker") &&
            !iface.name.startsWith("br-") &&
            !iface.name.startsWith("veth")
        )
        
        
            .forEach(iface => {
                const option = document.createElement("option");

                option.value = iface.name;

                const ip = iface.ip || "No IPv4";
                const status = iface.status === "up" ? "UP" : "DOWN";

                option.textContent =
                    `${iface.name} — ${ip} — ${status}`;

                elements.networkSelector.appendChild(option);
            });

        if (interfaces.length > 0) {
            selectedNetwork = elements.networkSelector.value;
        }

    } catch (error) {
        console.error("Failed to load interfaces:", error);

        elements.networkSelector.innerHTML =
            `<option value="">Unable to load interfaces</option>`;
    }
}

// --------------------------------------------------

async function loadDashboard() {

    try {

        elements.refreshButton.disabled = true;

        elements.refreshButton.textContent =
            "Refreshing...";


        const [
         health,
         stats,
         anomalies,
         events,
         alerts
        ] = await Promise.all([

            apiRequest("/api/health"),

            apiRequest(
                `/api/stats?network=${encodeURIComponent(selectedNetwork)}`
            ),

            apiRequest(
                `/api/anomalies?size=10&network=${encodeURIComponent(selectedNetwork)}`
            ),

            apiRequest(
                `/api/events?size=10&network=${encodeURIComponent(selectedNetwork)}`
            ),

            apiRequest(
                `/api/alerts?size=10&network=${encodeURIComponent(selectedNetwork)}`
            )

        ]);


        console.log("Health:", health);

        console.log("Stats:", stats);

        console.log("Anomalies:", anomalies);

        console.log("Events:", events);

        console.log("Alerts:", alerts);

        


        if (health.status !== "healthy") {
            throw new Error("API unhealthy");
        }


        elements.apiStatus.textContent =
            "API ONLINE";

        elements.statusDot.className =
            "status-dot online";


                renderStats(stats);

        renderAnomalies(
            anomalies.anomalies || []
        );

        if (elements.eventsTable) {
            renderEvents(
                events.events || []
            );
        }

        if (elements.alertsTable) {
            renderAlerts(
                alerts.alerts || []
            );
        }


    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );


        elements.apiStatus.textContent =
            "API OFFLINE";

        elements.statusDot.className =
            "status-dot offline";


        elements.eventsCount.textContent =
            "ERROR";

        elements.anomaliesCount.textContent =
            "ERROR";

        elements.hostsCount.textContent =
            "ERROR";

    } finally {

        elements.refreshButton.disabled = false;

        elements.refreshButton.textContent =
            "Refresh";
    }
}


// --------------------------------------------------
// Modal
// --------------------------------------------------

if (elements.modalClose && elements.modal) {

    elements.modalClose.addEventListener(
        "click",
        () => {
            elements.modal.classList.remove("visible");
        }
    );

    elements.modal.addEventListener(
        "click",
        event => {

            if (event.target === elements.modal) {
                elements.modal.classList.remove("visible");
            }

        }
    );
}


// --------------------------------------------------
// Start
// --------------------------------------------------
// --------------------------------------------------
// Start
// --------------------------------------------------
if (elements.networkSelector) {
    loadInterfaces();
    loadSelectedInterface();
}

if (elements.anomaliesTable) {
    loadDashboard();

    // Refresh every 10 seconds
    setInterval(
        loadDashboard,
        10000
    );
}
