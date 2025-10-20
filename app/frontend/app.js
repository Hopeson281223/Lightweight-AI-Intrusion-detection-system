class LAIIDSFrontend {
    constructor() {
        this.baseUrl = window.location.origin;
        this.isCapturing = false;
        this.ws = null;
        this.chart = null;
        this.alertCount = 0;
        this.unreadAlertCount = 0;
        this.reportsChart = null;
        
        this.init();
    }

    init() {
        console.log("🔄 Initializing LAI-IDS Frontend...");
        this.bindEvents();
        this.bindNavbar();
        this.loadInterfaces();
        this.initThreatChart();
        this.updateStats();
        this.loadModelInfo();
        this.startWebSocket();
        this.loadReports();
        this.updateModelStatus();

        // Set up intervals
        setInterval(() => this.updateStats(), 4000);
        setInterval(() => this.updateSystemInfo(), 5000);
        
        console.log("✅ Frontend initialized");
    }

    bindNavbar() {
        const hamburger = document.getElementById("hamburger");
        const navLinks = document.getElementById("navLinks");

        // Hamburger menu toggle
        hamburger.addEventListener("click", (e) => {
            e.stopPropagation();
            navLinks.classList.toggle("show");
            
            // Toggle hamburger icon
            const icon = hamburger.querySelector('i');
            icon.className = navLinks.classList.contains("show") ? "fas fa-times" : "fas fa-bars";
        });

        // Tab switching
        document.querySelectorAll(".nav-tab").forEach(tab => {
            tab.addEventListener("click", () => {
                const targetTab = tab.getAttribute("data-tab");
                this.switchToTab(targetTab);
            });
        });

        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.navbar') && navLinks.classList.contains('show')) {
                navLinks.classList.remove("show");
                const icon = hamburger.querySelector('i');
                icon.className = "fas fa-bars";
            }
        });

        // Close menu on window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth > 768 && navLinks.classList.contains('show')) {
                navLinks.classList.remove("show");
                const icon = hamburger.querySelector('i');
                icon.className = "fas fa-bars";
            }
        });
    }

    switchToTab(tabId) {
        // Remove active class from all tabs and panes
        document.querySelectorAll(".nav-tab").forEach(tab => {
            tab.classList.remove("active");
        });
        document.querySelectorAll(".tab-pane").forEach(pane => {
            pane.classList.remove("active");
        });
        
        // Add active class to clicked tab and corresponding pane
        const activeTab = document.querySelector(`[data-tab="${tabId}"]`);
        const activePane = document.getElementById(tabId);
        
        if (activeTab && activePane) {
            activeTab.classList.add("active");
            activePane.classList.add("active");
            console.log(`🔍 Switched to tab: ${tabId}`);
            
            // Handle tab-specific actions
            this.onTabActivated(tabId); // ADD THIS LINE
        }

        // Close mobile menu if open
        if (window.innerWidth <= 768) {
            const navLinks = document.getElementById("navLinks");
            const hamburger = document.getElementById("hamburger");
            navLinks.classList.remove("show");
            const icon = hamburger.querySelector('i');
            icon.className = "fas fa-bars";
        }
    }

    onTabActivated(tabId) {
        switch(tabId) {
            case 'threatTab':
                // Refresh chart when threat tab is activated
                setTimeout(() => {
                    if (this.chart) {
                        this.chart.resize(); // Properly resize the chart
                        this.chart.render(); // Ensure it's fully rendered
                        console.log("📊 Chart resized and rendered for threat tab");
                    }
                }, 100);
                break;
                
            case 'alertsTab':
                this.markAlertsAsRead();
                break;
                
            case 'statsTab':
                this.updateStats();
                break;

            case 'reportsTab': // NEW: Handle reports tab activation
                this.loadReports();
                this.initReportsChart();
                break;
        }
    }

    async loadReports() {
        try {
            const response = await this.apiCall('/reports');
            this.displayReports(response.reports || []);
            console.log(`📋 Loaded ${response.reports?.length || 0} reports`);
        } catch (error) {
            console.error('Error loading reports:', error);
            this.displayReports([]);
        }
    }

    displayReports(reports) {
        const tbody = document.getElementById('reportsBody');
        if (!tbody) return;

        if (!reports || reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No reports found.</td></tr>';
            return;
        }

        tbody.innerHTML = reports.map(report => {
            const createdDate = new Date(report.created_at).toLocaleString();
            const startTime = report.start_time ? new Date(report.start_time).toLocaleDateString() : 'N/A';
            const interfaceName = report.interface || 'Unknown';
            
            // Parse report data to get threat count
            let threatCount = 0;
            try {
                const reportData = JSON.parse(report.report_data);
                threatCount = reportData.predictions?.ANOMALOUS || 0;
            } catch (e) {
                console.warn('Could not parse report data:', e);
            }

            // Generate PDF filename for the "File" column
            const pdfFilename = `LAI-IDS_Report_${report.session_id}.pdf`;

            return `
                <tr>
                    <td>${createdDate}</td>
                    <td>Session Report</td>
                    <td>${threatCount} threats detected</td>
                    <td>${pdfFilename}</td>
                    <td>
                        <button class="btn btn-sm btn-info view-report" data-session="${report.session_id}">
                            <i class="fas fa-eye"></i> View
                        </button>
                        <button class="btn btn-sm btn-success download-report" data-session="${report.session_id}">
                            <i class="fas fa-download"></i> PDF
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        // Add event listeners to the new buttons
        this.bindReportActions();
    }

    bindReportActions() {
        // View report buttons
        document.querySelectorAll('.view-report').forEach(button => {
            button.addEventListener('click', (e) => {
                const sessionId = e.target.closest('button').dataset.session;
                this.viewReport(sessionId);
            });
        });

        // Download report buttons
        document.querySelectorAll('.download-report').forEach(button => {
            button.addEventListener('click', (e) => {
                const sessionId = e.target.closest('button').dataset.session;
                this.downloadReport(sessionId);
            });
        });

    
        // Refresh reports button
        const refreshBtn = document.getElementById('refreshReportsBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadReports());
        }

        // Search filter
        const searchInput = document.getElementById('reportSearch');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.filterReports(e.target.value));
        }

        // Type filter
        const typeFilter = document.getElementById('reportTypeFilter');
        if (typeFilter) {
            typeFilter.addEventListener('change', (e) => this.filterReportsByType(e.target.value));
        }
    }

    async viewReport(sessionId) {
        try {
            const report = await this.apiCall(`/reports/${sessionId}`);
            
            // Create a modal or overlay to display the report
            this.showReportModal(report, sessionId);
            
        } catch (error) {
            console.error('Error viewing report:', error);
            alert('Could not load report details. Please try again.');
        }
    }

    showReportModal(reportData, sessionId) {
        // Create modal overlay
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        `;

        // Modal content
        modal.innerHTML = `
            <div class="modal-content" style="
                background: white;
                padding: 30px;
                border-radius: 12px;
                max-width: 800px;
                max-height: 80vh;
                overflow-y: auto;
                box-shadow: 0 10px 50px rgba(0,0,0,0.3);
                position: relative;
            ">
                <button class="close-btn" style="
                    position: absolute;
                    top: 15px;
                    right: 15px;
                    background: none;
                    border: none;
                    font-size: 24px;
                    cursor: pointer;
                    color: #666;
                ">×</button>
                
                <h2 style="color: #2c3e50; margin-bottom: 20px;">
                    <i class="fas fa-file-alt"></i> Session Report: ${sessionId}
                </h2>
                
                <div class="report-details">
                    ${this.formatReportForDisplay(reportData)}
                </div>
                
                <div style="margin-top: 25px; display: flex; gap: 10px;">
                    <button class="btn btn-success download-in-modal" data-session="${sessionId}">
                        <i class="fas fa-download"></i> Download PDF
                    </button>
                    <button class="btn btn-secondary close-modal">
                        <i class="fas fa-times"></i> Close
                    </button>
                </div>
            </div>
        `;

        // Add event listeners
        modal.querySelector('.close-btn').addEventListener('click', () => modal.remove());
        modal.querySelector('.close-modal').addEventListener('click', () => modal.remove());
        modal.querySelector('.download-in-modal').addEventListener('click', (e) => {
            this.downloadReport(sessionId);
            modal.remove();
        });

        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });

        document.body.appendChild(modal);
    }

    formatReportForDisplay(reportData) {
        const session = reportData.session || {};
        const predictions = reportData.predictions || {};
        const alerts = reportData.alerts || [];

        // Clean up interface name for display
        let interfaceName = session.interface || 'N/A';
        if (interfaceName.includes('\\Device\\NPF_')) {
            interfaceName = 'Network Adapter';
        }

        // Format dates properly - handle both ISO format and local format
        const formatDate = (dateString) => {
            if (!dateString || dateString === 'N/A') return 'N/A';
            try {
                // If it's already in a readable format, return as is
                if (dateString.includes(', ')) {
                    return dateString;
                }
                // Otherwise parse and format
                return new Date(dateString).toLocaleString();
            } catch {
                return dateString;
            }
        };

        let html = `
            <div class="report-section">
                <h3 style="color: #3498db; margin-bottom: 15px;">
                    <i class="fas fa-info-circle"></i> Session Information
                </h3>
                <div class="info-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 20px;">
                    <div><strong>Interface:</strong> ${interfaceName}</div>
                    <div><strong>Start Time:</strong> ${formatDate(session.start_time)}</div>
                    <div><strong>End Time:</strong> ${formatDate(session.end_time)}</div>
                    <div><strong>Total Packets:</strong> ${session.total_packets || 0}</div>
                    <div><strong>Total Predictions:</strong> ${session.total_predictions || 0}</div>
                    <div><strong>Total Alerts:</strong> ${session.total_alerts || 0}</div>
                </div>
            </div>

            <div class="report-section">
                <h3 style="color: #3498db; margin-bottom: 15px;">
                    <i class="fas fa-chart-bar"></i> Prediction Summary
                </h3>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                    ${Object.entries(predictions).map(([label, count]) => `
                        <div style="display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #eee;">
                            <span style="font-weight: 600; color: ${label === 'ANOMALOUS' ? '#e74c3c' : '#27ae60'}">${label}:</span>
                            <span>${count}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        if (alerts.length > 0) {
            html += `
                <div class="report-section">
                    <h3 style="color: #3498db; margin-bottom: 15px;">
                        <i class="fas fa-bell"></i> Recent Alerts (${alerts.length})
                    </h3>
                    <div style="max-height: 200px; overflow-y: auto;">
                        ${alerts.map(alert => `
                            <div style="background: ${this.getAlertColor(alert.severity)}; padding: 10px; margin: 5px 0; border-radius: 6px; border-left: 4px solid ${this.getAlertBorderColor(alert.severity)}">
                                <div style="display: flex; justify-content: space-between;">
                                    <strong>${alert.severity}</strong>
                                    <small>${formatDate(alert.created_at)}</small>
                                </div>
                                <div style="margin-top: 5px;">${alert.message}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        return html;
    }

    getAlertColor(severity) {
        const colors = {
            'Critical': '#ffe6e6',
            'High': '#fff0e6',
            'Medium': '#fff9e6',
            'Low': '#e6f7ff'
        };
        return colors[severity] || '#f8f9fa';
    }

    getAlertBorderColor(severity) {
        const colors = {
            'Critical': '#e74c3c',
            'High': '#f39c12',
            'Medium': '#f1c40f',
            'Low': '#3498db'
        };
        return colors[severity] || '#bdc3c7';
    }

    downloadReport(sessionId) {
        // Open the download endpoint in a new tab/window
        window.open(`${this.baseUrl}/reports/${sessionId}/download`, '_blank');
    }

    filterReports(searchTerm) {
        const rows = document.querySelectorAll('#reportsBody tr');
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchTerm.toLowerCase()) ? '' : 'none';
        });
    }

    filterReportsByType(type) {
        const rows = document.querySelectorAll('#reportsBody tr');
        rows.forEach(row => {
            if (type === 'all') {
                row.style.display = '';
                return;
            }
            
            const reportType = row.cells[1].textContent.toLowerCase();
            row.style.display = reportType.includes(type.toLowerCase()) ? '' : 'none';
        });
    }

    initReportsChart() {
        const ctx = document.getElementById('reportChart');
        if (!ctx) {
            console.warn('Report chart canvas not found');
            return;
        }

        // Properly destroy existing chart
        if (this.reportsChart) {
            this.reportsChart.destroy();
            this.reportsChart = null;
        }

        // Get real data instead of static sample data
        const chartData = this.getReportsChartData();
        
        this.reportsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Sessions', 'Alerts', 'Threats', 'Packets'],
                datasets: [{
                    label: 'Current Statistics',
                    data: chartData,
                    backgroundColor: [
                        'rgba(52, 152, 219, 0.8)',
                        'rgba(231, 76, 60, 0.8)',
                        'rgba(243, 156, 18, 0.8)',
                        'rgba(46, 204, 113, 0.8)'
                    ],
                    borderColor: [
                        'rgb(52, 152, 219)',
                        'rgb(231, 76, 60)',
                        'rgb(243, 156, 18)',
                        'rgb(46, 204, 113)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0 // Only show whole numbers
                        },
                        // Prevent infinite scaling
                        suggestedMax: Math.max(...chartData) * 1.2 || 10
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Current Session Overview'
                    }
                },
                // Prevent chart animation from causing overflow
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart'
                },
                // Ensure chart stays within bounds
                layout: {
                    padding: {
                        left: 10,
                        right: 10,
                        top: 10,
                        bottom: 10
                    }
                }
            }
        });

        console.log('📊 Reports chart initialized with data:', chartData);
    }

    getReportsChartData() {
        try {
            // Get actual data from current UI elements and stats
            const packetsElement = document.getElementById('packetsCaptured');
            const alertsElement = document.getElementById('alertBadge');
            
            const packets = packetsElement ? parseInt(packetsElement.textContent) || 0 : 0;
            const alerts = alertsElement ? parseInt(alertsElement.textContent) || 0 : 0;
            
            // For sessions count - you might want to get this from your API
            // For now, we'll use a reasonable estimate
            const sessions = 1; // Current active session
            
            // For threats - estimate based on alerts or get from threat distribution
            const threats = Math.max(0, Math.floor(alerts * 0.7)); // Estimate threats from alerts
            
            return [sessions, alerts, threats, packets];
        } catch (error) {
            console.warn('Could not get chart data from DOM:', error);
            return [1, 0, 0, 0]; // Fallback to minimal data
        }
    }

    updateReportsChart() {
        if (!this.reportsChart) return;
        
        const newData = this.getReportsChartData();
        this.reportsChart.data.datasets[0].data = newData;
        
        // Update the suggested max for y-axis
        this.reportsChart.options.scales.y.suggestedMax = Math.max(...newData) * 1.2 || 10;
        
        this.reportsChart.update('none'); // 'none' prevents animation that could cause overflow
        console.log('📈 Reports chart updated with new data:', newData);
    }

    updateAlertBadge() {
        const badge = document.getElementById("alertBadge");
        if (!badge) return;
        
        const alertsTab = document.querySelector('[data-tab="alertsTab"]');
        const isOnAlertsTab = alertsTab && alertsTab.classList.contains('active');
        
        // Only show badge if:
        // 1. There are unread alerts AND
        // 2. User is NOT currently on the alerts tab
        const shouldShowBadge = this.unreadAlertCount > 0 && !isOnAlertsTab;
        
        badge.textContent = this.unreadAlertCount;
        
        if (shouldShowBadge) {
            badge.classList.add("show");
            
            // Add pulse animation for new alerts
            badge.style.animation = 'pulse 1s 3';
            setTimeout(() => {
                badge.style.animation = '';
            }, 3000);
        } else {
            badge.classList.remove("show");
            badge.style.animation = '';
        }
        
        console.log(`🔴 Alert badge: ${this.unreadAlertCount} unread, on alerts tab: ${isOnAlertsTab}, showing: ${shouldShowBadge}`);
    }

    markAlertsAsRead() {
        // Reset unread alert count
        this.unreadAlertCount = 0; // ✅ CORRECT - reset to zero
        
        // Update the badge display
        this.updateAlertBadge();
        
        // Remove any visual indicators from alerts tab
        const alertsTab = document.querySelector('[data-tab="alertsTab"]');
        if (alertsTab) {
            alertsTab.style.animation = '';
        }
        
        console.log("🔔 Alerts marked as read - unread count reset to 0");
    }

    incrementAlertCount() {
        // Increment both total and unread counts
        this.alertCount++;
        this.unreadAlertCount++;
        
        // Update the badge display
        this.updateAlertBadge();
        
        console.log(`📈 Alert count: ${this.alertCount} total, ${this.unreadAlertCount} unread`);
    }

    async updateSystemInfo() {
        try {
            const res = await this.apiCall("/system");
            document.getElementById("cpuUsage").textContent = `${res.cpu}%`;
            document.getElementById("memUsage").textContent = `${res.memory}%`;
            document.getElementById("uptime").textContent = res.uptime || "--";
        } catch {
            document.getElementById("cpuUsage").textContent = "N/A";
            document.getElementById("memUsage").textContent = "N/A";
            document.getElementById("uptime").textContent = "--";
        }
    }

    bindEvents() {
        document.getElementById('startBtn').addEventListener('click', () => this.startCapture());
        document.getElementById('stopBtn').addEventListener('click', () => this.stopCapture());
        document.getElementById('refreshBtn').addEventListener('click', () => this.updateStats());

        document.getElementById('interfaceSelect').addEventListener('change', () => {
            this.updateInterfaceStatus();
        });

        document.getElementById('modelSelect').addEventListener('change', () => {
            this.updateModelStatus();
        });
    }

    async apiCall(endpoint, method = 'GET', body = null) {
        try {
            const res = await fetch(`${this.baseUrl}${endpoint}`, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: body ? JSON.stringify(body) : null
            });
            if (!res.ok) throw new Error(await res.text());
            return await res.json();
        } catch (error) {
            console.error(`API Call failed for ${endpoint}:`, error);
            throw error;
        }
    }

    async loadInterfaces() {
        try {
            const data = await this.apiCall('/interfaces');
            const select = document.getElementById('interfaceSelect');
            select.innerHTML = '';

            if (data.interfaces && data.interfaces.length > 0) {
                let activeInterfaceFound = false;
                let firstActiveInterface = null;

                data.interfaces.forEach(iface => {
                    const opt = document.createElement('option');
                    opt.value = iface.device;
                    
                    // Add active indicator to the option text
                    const activeIndicator = iface.active ? '🟢 ACTIVE - ' : '⚫ ';
                    opt.textContent = `${activeIndicator}${iface.name} — ${iface.description}`;
                    
                    // Add data attribute for styling
                    opt.dataset.active = iface.active;
                    
                    select.appendChild(opt);

                    // Track the first active interface for auto-selection
                    if (iface.active && !firstActiveInterface) {
                        firstActiveInterface = iface;
                    }
                });

                // Auto-select the first active interface, or first available
                if (firstActiveInterface) {
                    select.value = firstActiveInterface.device;
                    activeInterfaceFound = true;
                    this.showAutoSelectNotification(firstActiveInterface.name);
                } else if (data.interfaces.length > 0) {
                    // Fallback to first interface if no active ones found
                    select.value = data.interfaces[0].device;
                }

                // Update interface status display
                this.updateInterfaceStatus();
                
            } else {
                select.innerHTML = '<option disabled>No interfaces found</option>';
            }
        } catch (err) {
            console.error("Error loading interfaces:", err);
            this.log("Error loading interfaces", "error");
        }
    }

    styleActiveInterfaces() {
        const select = document.getElementById('interfaceSelect');
        if (!select) return;

        // Add CSS for styling active interfaces if not already added
        if (!document.getElementById('interfaceStyles')) {
            const style = document.createElement('style');
            style.id = 'interfaceStyles';
            style.textContent = `
                .active-interface {
                    background: linear-gradient(90deg, #e8f5e8 0%, #f0f8f0 100%) !important;
                    border-left: 3px solid #27ae60 !important;
                    font-weight: 600 !important;
                }
                .interface-active-badge {
                    display: inline-block;
                    width: 8px;
                    height: 8px;
                    background: #27ae60;
                    border-radius: 50%;
                    margin-right: 8px;
                }
            `;
            document.head.appendChild(style);
        }

        // Apply styling to options
        Array.from(select.options).forEach(option => {
            if (option.dataset.active === 'true') {
                option.classList.add('active-interface');
            }
        });
    }

    updateModelStatus() {
        const statusElement = document.getElementById('modelStatus');
        const select = document.getElementById('modelSelect');
        
        if (!statusElement || !select) return;
        
        const selectedModel = select.value;
        const isAvailable = this.checkModelAvailability(selectedModel);
        
        statusElement.className = `model-status ${isAvailable ? 'active' : 'inactive'}`;
        statusElement.innerHTML = `
            <span class="status-dot ${isAvailable ? 'active' : 'inactive'}"></span>
            <span class="status-text">${isAvailable ? 'AVAILABLE' : 'NOT FOUND'}</span>
        `;
        statusElement.style.display = 'flex';
        
        // Update description
        const description = statusElement.querySelector('.model-description');
        if (description) {
            description.textContent = this.getModelDescription(selectedModel);
        }
    }

    getModelDescription(modelType) {
        const descriptions = {
            'random_forest': '99.86% accuracy - Best for detection',
            'decision_tree': 'Fast inference - Good for monitoring'
        };
        return descriptions[modelType] || 'Model information';
    }

    async startCapture() {
        const iface = document.getElementById('interfaceSelect').value;
        const modelType = document.getElementById('modelSelect').value;
        
        if (!iface || iface.includes('Loading') || iface.includes('No interfaces')) {
            this.log("Please select a valid network interface", "error");
            return;
        }

        try {
            await this.apiCall(`/start?interface=${encodeURIComponent(iface)}`, 'POST');
            this.isCapturing = true;
            this.log(`Started capturing on interface: ${iface} using ${modelType.toUpperCase()} model`, 'success');
            this.updateSystemStatus(true);
            document.getElementById('startBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
        } catch (err) {
            this.log(`Failed to start capture: ${err.message}`, "error");
        }
    }


    async stopCapture() {
        try {
            const data = await this.apiCall('/stop', 'POST');
            this.isCapturing = false;
            this.log(data.message, 'info');
            this.updateSystemStatus(false);
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
            document.getElementById('captureStatus').textContent = cs.is_capturing ? 'Running' : 'Stopped';
            document.getElementById('currentInterface').textContent = cs.interface || '--';

            console.log('📊 Raw threat distribution:', stats.threat_distribution);

            this.updateThreatChart(stats.threat_distribution || {});
            
            // Also update reports chart if it exists and we're on reports tab
            if (this.reportsChart && document.getElementById('reportsTab').classList.contains('active')) {
                this.updateReportsChart();
            }
        } catch (err) {
            this.log(`Error fetching stats: ${err}`, 'error');
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
        const ctx = document.getElementById('threatChart');
        if (!ctx) {
            console.error('Threat chart canvas not found!');
            return;
        }

        // Set fixed dimensions
        ctx.style.minHeight = '250px';
        ctx.style.maxHeight = '300px';
        ctx.style.width = '100%';

        this.chart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['NO DATA'], // Single label for no data state
                datasets: [{
                    data: [100], // Single segment that fills the whole chart
                    backgroundColor: ['#ecf0f1'], // Light gray color
                    borderWidth: 0, // No border for cleaner look
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%', // Keep the doughnut hole
                plugins: {
                    legend: {
                        display: false, // Hide legend in no data state
                    },
                    tooltip: {
                        enabled: false // Disable tooltips when no data
                    }
                },
                animation: {
                    duration: 500,
                    animateScale: false
                }
            }
        });
        
        console.log('✅ Threat chart initialized in "no data" state');
    }

    updateThreatChart(dist) {
        if (!this.chart) {
            console.warn('Chart not initialized');
            return;
        }
        
        // Get the threat card element
        const threatCard = document.querySelector('.threat-card');
        
        console.log('📊 Raw threat distribution:', dist);
        
        // Extract values safely
        let normal = 0, anomalous = 0;
        
        if (typeof dist === 'object' && dist !== null) {
            normal = parseInt(dist.NORMAL) || 0;
            anomalous = parseInt(dist.ANOMALOUS) || 0;
        }
        
        console.log(`📊 Raw threat data: NORMAL=${normal}, ANOMALOUS=${anomalous}`);
        
        const total = normal + anomalous;
        
        if (total === 0) {
            // NO DATA STATE
            this.chart.data.labels = ['NO DATA'];
            this.chart.data.datasets[0].data = [100];
            this.chart.data.datasets[0].backgroundColor = ['#ecf0f1'];
            this.chart.data.datasets[0].borderWidth = 0;
            
            this.chart.options.plugins.legend.display = false;
            this.chart.options.plugins.tooltip.enabled = false;
            
            // Add no-data CSS class
            if (threatCard) {
                threatCard.classList.add('no-data');
            }
            
            console.log('📊 Chart: No data available - showing empty state');
        } else {
            // WE HAVE DATA
            this.chart.data.labels = ['NORMAL', 'ANOMALOUS'];
            this.chart.data.datasets[0].data = [normal, anomalous];
            this.chart.data.datasets[0].backgroundColor = ['#2ecc71', '#e74c3c'];
            this.chart.data.datasets[0].borderWidth = 3;
            this.chart.data.datasets[0].borderColor = '#fff';
            
            this.chart.options.plugins.legend.display = true;
            this.chart.options.plugins.tooltip.enabled = true;
            
            // Remove no-data CSS class
            if (threatCard) {
                threatCard.classList.remove('no-data');
            }
            
            const normalPercent = (normal / total * 100).toFixed(1);
            const anomalousPercent = (anomalous / total * 100).toFixed(1);
            console.log(`📈 Chart update: ${normal} normal (${normalPercent}%), ${anomalous} anomalous (${anomalousPercent}%)`);
        }
        
        this.chart.update('active');
    }

    updateInterfaceStatus(selectedInterface) {
        const statusElement = document.getElementById('interfaceStatus');
        const select = document.getElementById('interfaceSelect');
        const currentInterfaceSpan = document.getElementById('currentInterface');
        
        if (!statusElement || !select || !currentInterfaceSpan) return;
        
        const selectedOption = select.selectedOptions[0];
        if (selectedOption && selectedOption.value !== 'Loading...') {
            const isActive = selectedOption.dataset.active === 'true';
            
            // Update status display
            statusElement.className = `interface-status ${isActive ? 'active' : 'inactive'}`;
            statusElement.innerHTML = `
                <span class="status-dot ${isActive ? 'active' : 'inactive'}"></span>
                <span class="status-text">${isActive ? 'ACTIVE' : 'INACTIVE'}</span>
            `;
            statusElement.style.display = 'flex';
            
            // Update current interface display
            const interfaceName = selectedOption.textContent.replace(/[🟢⚫]/g, '').trim();
            currentInterfaceSpan.textContent = interfaceName;
            currentInterfaceSpan.style.color = isActive ? '#28a745' : '#dc3545';
            currentInterfaceSpan.style.fontWeight = '700';
        }
    }

    startWebSocket() {
        try {
            const ws = new WebSocket(`ws://${window.location.host}/ws/logs`);
            
            ws.onopen = () => {
                this.log("WebSocket connection established", "success");
                this.updateSystemStatus(this.isCapturing);
            };
            
            ws.onmessage = e => {
                try {
                    const data = JSON.parse(e.data);
                    this.addStructuredLog(data);
                } catch {
                    this.addLogEntry(e.data);
                }
            };
            
            ws.onclose = () => {
                this.log("WebSocket connection closed, reconnecting...", "warn");
                setTimeout(() => this.startWebSocket(), 5000);
            };
            
            this.ws = ws;
        } catch (error) {
            setTimeout(() => this.startWebSocket(), 5000);
        }
    }

    addLogEntry(message) {
        const logContainer = document.getElementById('captureLog');
        if (!logContainer) return;

        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;

        if (message.includes('ANOMALOUS')) {
            this.addAlert(message);
        }

        if (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.firstChild);
        }
    }

    addStructuredLog(data) {
        const logContainer = document.getElementById('captureLog');
        if (!logContainer) return;

        const entry = document.createElement('div');
        entry.classList.add('log-entry');

        if (data.label === 'ANOMALOUS') entry.classList.add('error');
        else if (data.label === 'NORMAL') entry.classList.add('info');
        else entry.classList.add('warn');

        const confidence = data.confidence ? data.confidence.toFixed(2) : 'N/A';
        const proto = data.protocol || 'N/A';
        const src = data.src_ip || 'N/A';
        const dst = data.dst_ip || 'N/A';

        entry.textContent = `[${data.timestamp}] ${src} → ${dst} | ${proto} | ${data.label} (${confidence})`;

        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;

        if (data.label === 'ANOMALOUS') {
            this.addAlertFromLog(data);
        }

        if (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.firstChild);
        }
    }

    addAlert(message) {
        const tbody = document.getElementById('alertsBody');
        if (!tbody) return;

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

        this.incrementAlertCount();
    }

    addAlertFromLog(data) {
        const tbody = document.getElementById('alertsBody');
        if (!tbody) return;

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
        this.incrementAlertCount();
    }

    log(msg, type = 'info') {
        const logContainer = document.getElementById('captureLog');
        if (!logContainer) return;

        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    updateSystemStatus(running) {
        const dot = document.querySelector('.status-dot');
        const text = document.querySelector('.status-text');
        
        if (!dot || !text) return;

        if (running) {
            dot.className = 'status-dot connected';
            text.textContent = 'Capturing';
        } else {
            dot.className = 'status-dot stopped';
            text.textContent = 'Stopped';
        }
    }
    
}

let app; // Make app global for testing
document.addEventListener('DOMContentLoaded', () => {
    app = new LAIIDSFrontend();
    window.app = app; // Expose to console for debugging
});