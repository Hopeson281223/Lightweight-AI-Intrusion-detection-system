class LAIIDSFrontend {
    constructor() {
        this.baseUrl = window.location.origin;
        this.isCapturing = false;
        this.updateInterval = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadInterfaces();
        this.updateStats();
        this.startAutoRefresh();
        this.log('Frontend initialized', 'info');
    }

    bindEvents() {
        document.getElementById('startBtn').addEventListener('click', () => this.startCapture());
        document.getElementById('stopBtn').addEventListener('click', () => this.stopCapture());
        document.getElementById('refreshBtn').addEventListener('click', () => this.manualRefresh());
        document.getElementById('interfaceSelect').addEventListener('change', (e) => this.setInterface(e.target.value));
    }

    async apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`API call failed for ${endpoint}:`, error);
            throw error;
        }
    }

    async startCapture() {
        const iface = document.getElementById('interfaceSelect').value;
        if (!iface) {
            this.showError('Please select a network interface first');
            return;
        }

        try {
            this.log('Starting packet capture...', 'info');
            const data = await this.apiCall(`/start?interface=${encodeURIComponent(iface)}`, { method: 'POST' });
            this.isCapturing = true;
            this.updateUI();
            this.log(`Capture started on ${data.interface}`, 'success');
        } catch (error) {
            this.showError(`Failed to start capture: ${error.message}`);
        }
    }

    async stopCapture() {
        try {
            this.log('Stopping packet capture...', 'info');
            const data = await this.apiCall('/stop', { method: 'POST' });
            this.isCapturing = false;
            this.updateUI();
            this.log(`Capture stopped. ${data.message}`, 'success');
        } catch (error) {
            this.showError(`Failed to stop capture: ${error.message}`);
        }
    }

    async setInterface(iface) {
        if (!iface) return;

        try {
            await this.apiCall(`/interface/${encodeURIComponent(iface)}`, { method: 'POST' });
            this.log(`Interface set to: ${iface}`, 'success');
        } catch (error) {
            this.showError(`Error setting interface: ${error.message}`);
        }
    }

    async loadInterfaces() {
        try {
            const data = await this.apiCall('/interfaces');
            const select = document.getElementById('interfaceSelect');
            select.innerHTML = '';

            data.interfaces.forEach((iface) => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                select.appendChild(option);
            });

            if (data.interfaces.length > 0) {
                select.value = data.interfaces[0];
                this.setInterface(data.interfaces[0]);
            }
        } catch (error) {
            this.log('Error loading interfaces', 'error');
            console.error('Error loading interfaces:', error);
        }
    }

    async updateStats() {
        try {
            const stats = await this.apiCall('/stats');
            const captureStatus = stats.capture_status || {};

            document.getElementById('captureStatus').textContent = captureStatus.is_capturing ? 'Running' : 'Stopped';
            document.getElementById('packetsCaptured').textContent = captureStatus.packets_captured || 0;
            document.getElementById('activeFlows').textContent = captureStatus.active_flows || 0;
            document.getElementById('totalPackets').textContent = stats.total_packets || 0;
            document.getElementById('recentAlerts').textContent = stats.recent_alerts || 0;

            this.updateThreatChart(stats.threat_distribution);
            this.updateSystemStatus(true);
        } catch (err) {
            this.log(`Error fetching stats: ${err}`, 'error');
            this.updateSystemStatus(false);
        }
    }

    updateThreatChart(threatDistribution) {
        const chart = document.getElementById('threatChart');
        if (!threatDistribution || Object.keys(threatDistribution).length === 0) {
            chart.innerHTML = '<div class="no-alerts">No traffic analyzed yet</div>';
            return;
        }

        const total = Object.values(threatDistribution).reduce((sum, val) => sum + val, 0);
        if (total === 0) {
            chart.innerHTML = '<div class="no-alerts">No threats detected</div>';
            return;
        }

        let chartHTML = '<div class="threat-bars">';
        Object.entries(threatDistribution).forEach(([label, count]) => {
            const percentage = (count / total) * 100;
            const threatClass = label.toLowerCase().includes('anomalous') ? 'anomalous' : 'normal';
            chartHTML += `
                <div class="threat-bar">
                    <div class="threat-label">
                        <span>${label}</span>
                        <span>${count} (${percentage.toFixed(1)}%)</span>
                    </div>
                    <div class="threat-bar-inner">
                        <div class="threat-fill ${threatClass}" style="width: ${percentage}%"></div>
                    </div>
                </div>
            `;
        });
        chartHTML += '</div>';
        chart.innerHTML = chartHTML;
    }

    updateSystemStatus(connected = true) {
        const statusIndicator = document.getElementById('systemStatus');
        const statusDot = statusIndicator.querySelector('.status-dot');
        const statusText = statusIndicator.querySelector('.status-text');

        if (connected) {
            statusDot.className = 'status-dot connected';
            statusText.textContent = this.isCapturing ? 'Capturing' : 'Connected';
        } else {
            statusDot.className = 'status-dot error';
            statusText.textContent = 'Disconnected';
        }
    }

    updateUI() {
        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        const interfaceSelect = document.getElementById('interfaceSelect');

        if (this.isCapturing) {
            startBtn.disabled = true;
            stopBtn.disabled = false;
            interfaceSelect.disabled = true;
            startBtn.innerHTML = '<i class="fas fa-play"></i> Capturing...';
        } else {
            startBtn.disabled = false;
            stopBtn.disabled = true;
            interfaceSelect.disabled = false;
            startBtn.innerHTML = '<i class="fas fa-play"></i> Start Capture';
        }
    }

    log(message, type = 'info') {
        const logContainer = document.getElementById('captureLog');
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;
        logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight;

        const entries = logContainer.querySelectorAll('.log-entry');
        if (entries.length > 50) entries[0].remove();
    }

    showError(message) {
        this.log(`ERROR: ${message}`, 'error');
        console.error(message);
    }

    startAutoRefresh() {
        this.updateInterval = setInterval(() => this.updateStats(), 2000);
    }

    manualRefresh() {
        this.updateStats();
        this.log('Manual refresh triggered', 'info');
    }

    destroy() {
        if (this.updateInterval) clearInterval(this.updateInterval);
    }
}

document.addEventListener('DOMContentLoaded', () => { window.laiidsApp = new LAIIDSFrontend(); });
