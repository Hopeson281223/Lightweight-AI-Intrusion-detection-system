class LAIIDSFrontend {
    constructor() {
        this.baseUrl = window.location.origin;
        this.isCapturing = false;
        this.ws = null;
        this.chart = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadInterfaces();
        this.initThreatChart();
        this.updateStats();
        this.loadModelInfo();
        this.startWebSocket();
        this.autoRefresh();
    }

    bindEvents() {
        document.getElementById('startBtn').addEventListener('click', () => this.startCapture());
        document.getElementById('stopBtn').addEventListener('click', () => this.stopCapture());
        document.getElementById('refreshBtn').addEventListener('click', () => this.updateStats());
    }

    async apiCall(endpoint, method = 'GET', body = null) {
        const res = await fetch(`${this.baseUrl}${endpoint}`, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: body ? JSON.stringify(body) : null
        });
        if (!res.ok) throw new Error(await res.text());
        return await res.json();
    }

    async loadInterfaces() {
        try {
            console.log("🔹 Fetching interfaces...");
            const data = await this.apiCall('/interfaces');
            console.log("✅ Interfaces fetched:", data);

            const select = document.getElementById('interfaceSelect');
            select.innerHTML = ''; // Clear old

            if (data.interfaces && data.interfaces.length > 0) {
                data.interfaces.forEach(iface => {
                    const opt = document.createElement('option');
                    opt.value = iface.device;
                    opt.textContent = `${iface.name} — ${iface.description}`;
                    select.appendChild(opt);
                });

                // Select the first interface automatically
                select.value = data.interfaces[0].device;
                document.getElementById('currentInterface').textContent = data.interfaces[0].name;
            } else {
                const opt = document.createElement('option');
                opt.textContent = 'No interfaces found';
                select.appendChild(opt);
            }
        } catch (err) {
            console.error("❌ Error loading interfaces:", err);
            this.log("Error loading interfaces", "error");
            const select = document.getElementById('interfaceSelect');
            select.innerHTML = '<option disabled>Error loading interfaces</option>';
        }
    }


    async startCapture() {
        const iface = document.getElementById('interfaceSelect').value;
        try {
            await this.apiCall(`/start?interface=${encodeURIComponent(iface)}`, 'POST');
            this.isCapturing = true;
            this.log(`Started capturing on interface:  ${iface}`, 'success');
            this.updateSystemStatus(true);

            // ✅ Disable Start, Enable Stop
            document.getElementById('startBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
        } catch (err) {
            this.log(`Failed to start capture: ${err.message}`, 'error');
        }
    }

    async stopCapture() {
        try {
            const data = await this.apiCall('/stop', 'POST');
            this.isCapturing = false;
            this.log(data.message, 'info');
            this.updateSystemStatus(false);

            // ✅ Enable Start, Disable Stop
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
        } catch (err) {
            this.log(`Failed to stop capture: ${err.message}`, 'error');
        }
    }

    async updateStats() {
        try {
            const stats = await this.apiCall('/stats');
            const cs = stats.capture_status || {};

            document.getElementById('packetsCaptured').textContent = cs.packets_captured || 0;
            document.getElementById('activeFlows').textContent = cs.active_flows || 0;
            document.getElementById('systemUptime').textContent = new Date().toLocaleTimeString();

            document.getElementById('captureStatus').textContent = cs.is_capturing ? 'Running' : 'Stopped';
            document.getElementById('systemHealth').textContent = 'OK';
            document.getElementById('currentInterface').textContent = cs.interface || '--';

            this.updateThreatChart(stats.threat_distribution || {});
        } catch (err) {
            this.log(`Error fetching stats: ${err}`, 'error');
            document.getElementById('systemHealth').textContent = 'Error';
        }
    }

    async loadModelInfo() {
        try {
            const models = await this.apiCall('/models');
            if (models.length > 0) {
                const latest = models[0];
                document.getElementById('mlModel').textContent = latest.name;
                document.getElementById('datasetName').textContent = latest.dataset;
                document.getElementById('modelSize').textContent = latest.size_kb.toFixed(2);
                document.getElementById('modelAccuracy').textContent = '≈90%';
            }
        } catch {
            this.log('No model info found', 'warn');
        }
    }

    initThreatChart() {
        const ctx = document.getElementById('threatChart').getContext('2d');
        this.chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['NORMAL', 'ANOMALOUS'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#2ecc71', '#e74c3c']
                }]
            },
            options: {
                plugins: { legend: { position: 'bottom' } },
                responsive: true
            }
        });
    }

    updateThreatChart(dist) {
        if (!this.chart) return;
        const normal = dist.NORMAL || 0;
        const anomalous = dist.ANOMALOUS || 0;
        this.chart.data.datasets[0].data = [normal, anomalous];
        this.chart.update();
    }

    startWebSocket() {
        const ws = new WebSocket(`ws://${window.location.host}/ws/logs`);
        ws.onmessage = e => {
            try {
                const data = JSON.parse(e.data);
                this.addStructuredLog(data);
            } catch {
                // fallback for legacy plain text logs
                this.addLogEntry(e.data);
            }
        };
        ws.onclose = () => setTimeout(() => this.startWebSocket(), 5000);
        this.ws = ws;
    }

    addLogEntry(message) {
        const logContainer = document.getElementById('captureLog');
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;

        // If anomalous, push to Alerts
        if (message.includes('ANOMALOUS')) {
            this.addAlert(message);
        }

        // Limit logs to 100 entries
        if (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.firstChild);
        }
    }

    addStructuredLog(data) {
        const logContainer = document.getElementById('captureLog');
        const entry = document.createElement('div');
        entry.classList.add('log-entry');

        // Assign color based on label
        if (data.label === 'ANOMALOUS') entry.classList.add('error');
        else if (data.label === 'NORMAL') entry.classList.add('info');
        else entry.classList.add('warn');

        // Format log text
        const confidence = data.confidence ? data.confidence.toFixed(2) : 'N/A';
        const proto = data.protocol || 'N/A';
        const src = data.src_ip || 'N/A';
        const dst = data.dst_ip || 'N/A';
        const msg = data.message || '';

        entry.textContent = `[${data.timestamp}] ${src} → ${dst} | ${proto} | ${data.label} (${confidence}) ${msg}`;

        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;

        // If anomalous, push to Alerts
        if (data.label === 'ANOMALOUS') {
            this.addAlertFromLog(data);
        }

        // Limit logs to 100
        if (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.firstChild);
        }
    }

    addAlert(message) {
        const tbody = document.getElementById('alertsBody');
        if (tbody.children[0] && tbody.children[0].children.length === 1)
            tbody.innerHTML = '';

        const row = document.createElement('tr');
        const confidence = message.match(/conf: (\d+\.\d+)/);
        const confVal = confidence ? confidence[1] : 'N/A';
        const severity = parseFloat(confVal) >= 0.9 ? 'Critical' : 'High';

        row.innerHTML = `
            <td>${new Date().toLocaleTimeString()}</td>
            <td>ANOMALOUS</td>
            <td>${confVal}</td>
            <td>${severity}</td>
        `;
        tbody.prepend(row);
    }

    addAlertFromLog(data) {
        const tbody = document.getElementById('alertsBody');
        if (tbody.children[0] && tbody.children[0].children.length === 1)
            tbody.innerHTML = '';

        const row = document.createElement('tr');
        const severity = data.confidence >= 0.9 ? 'Critical' : 'High';

        row.innerHTML = `
            <td>${data.timestamp}</td>
            <td>${data.label}</td>
            <td>${data.confidence ? data.confidence.toFixed(2) : 'N/A'}</td>
            <td>${severity}</td>
        `;

        tbody.prepend(row);
    }


    log(msg, type = 'info') {
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        const log = document.getElementById('captureLog');
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    updateSystemStatus(running) {
        const dot = document.querySelector('.status-dot');
        const text = document.querySelector('.status-text');
        if (running) {
            dot.className = 'status-dot connected';
            text.textContent = 'Capturing';
        } else {
            dot.className = 'status-dot stopped';
            text.textContent = 'Stopped';
        }
    }

    autoRefresh() {
        setInterval(() => this.updateStats(), 4000);
    }
}

document.addEventListener('DOMContentLoaded', () => new LAIIDSFrontend());
