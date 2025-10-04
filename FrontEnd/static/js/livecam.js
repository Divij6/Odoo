// static/js/livecam.js - AI Detection Control Interface (Flask-managed camera)
class AIDetectionController {
    constructor() {
        this.isDetectionActive = false;
        this.detectionCheckInterval = null;
        this.threatsCheckInterval = null;
        this.videoStreamInterval = null;
        this.recentDetections = [];
        this.maxRecentDetections = 10;
        this.lastThreatCheck = 0;

        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.startStatusMonitoring();
        this.startThreatsMonitoring();
        await this.checkInitialDetectionStatus();
        this.showNotification('System initialized', 'success');
    }

    setupEventListeners() {
        // Detection control buttons - try multiple possible IDs
        const startBtn = document.getElementById('startDetection') ||
                         document.querySelector('button[onclick*="start"]') ||
                         document.querySelector('.btn-primary');
        const stopBtn = document.getElementById('stopDetection') ||
                        document.querySelector('button[onclick*="stop"]') ||
                        document.querySelector('.btn-secondary');

        console.log('Found start button:', startBtn);
        console.log('Found stop button:', stopBtn);

        if (startBtn) {
            startBtn.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Start button clicked!');
                this.startDetection();
            });
        } else {
            console.error('Start button not found! Available buttons:', document.querySelectorAll('button'));
        }

        if (stopBtn) {
            stopBtn.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Stop button clicked!');
                this.stopDetection();
            });
        } else {
            console.error('Stop button not found!');
        }

        // Status refresh button
        const refreshBtn = document.getElementById('refreshStatus');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.checkDetectionStatus());
        }

        // Auto-refresh toggle
        const autoRefreshToggle = document.getElementById('autoRefresh');
        if (autoRefreshToggle) {
            autoRefreshToggle.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.startStatusMonitoring();
                    this.startThreatsMonitoring();
                } else {
                    this.stopStatusMonitoring();
                    this.stopThreatsMonitoring();
                }
            });
        }
    }

    startVideoStream() {
        this.stopVideoStream(); // Clear existing interval

        const video = document.getElementById('localCam');
        if (!video) {
            console.error('Video element with ID "localCam" not found');
            return;
        }

        // Set video source to Flask video stream endpoint
        video.src = '/video_feed';
        video.onload = () => {
            console.log('Video stream connected to Flask backend');
        };

        video.onerror = (e) => {
            console.error('Video stream error:', e);
            this.showNotification('Video stream connection failed', 'error');
        };
    }

    stopVideoStream() {
        const video = document.getElementById('localCam');
        if (video) {
            video.src = '';
            video.srcObject = null;
        }

        if (this.videoStreamInterval) {
            clearInterval(this.videoStreamInterval);
            this.videoStreamInterval = null;
        }
    }

    async startDetection() {
        try {
            this.setButtonLoading('startDetection', true);

            console.log('Starting AI detection...');

            // Start AI detection on the Flask backend
            const response = await fetch('/api/start_detection', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();
            console.log('Start detection response:', data);

            if (response.ok) {
                this.isDetectionActive = true;
                this.updateDetectionStatus('active');
                this.showNotification('AI Detection started - Camera and models running', 'success');
                this.addRecentDetection('System', 'AI Detection activated - Flask managing camera');

                // Start video stream from Flask
                this.startVideoStream();

                // Start monitoring for new threats
                this.startThreatsMonitoring();
            } else {
                throw new Error(data.error || 'Failed to start AI detection');
            }
        } catch (error) {
            console.error('Start detection failed:', error);
            this.showNotification(`Failed to start detection: ${error.message}`, 'error');
        } finally {
            this.setButtonLoading('startDetection', false);
        }
    }

    async stopDetection() {
        try {
            this.setButtonLoading('stopDetection', true);

            console.log('Stopping AI detection...');

            // Stop AI detection on Flask backend
            const response = await fetch('/api/stop_detection', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();
            console.log('Stop detection response:', data);

            if (response.ok) {
                this.isDetectionActive = false;
                this.updateDetectionStatus('inactive');
                this.showNotification('AI Detection stopped', 'warning');
                this.addRecentDetection('System', 'AI Detection deactivated');
            } else {
                console.warn('API stop failed but continuing with cleanup:', data.error);
                this.showNotification(`Warning: ${data.error || 'Stop API failed'} - but stopping locally`, 'warning');
            }

            // Always stop video stream regardless of API response
            this.stopVideoStream();
            this.stopThreatsMonitoring();

        } catch (error) {
            console.error('Stop detection failed:', error);
            this.showNotification(`Failed to stop detection: ${error.message}`, 'error');
            // Still stop video stream even if API call failed
            this.stopVideoStream();
            this.stopThreatsMonitoring();
        } finally {
            this.setButtonLoading('stopDetection', false);
        }
    }

    async checkDetectionStatus() {
        try {
            const response = await fetch('/api/detection_status');
            const data = await response.json();

            console.log('Detection status:', data);

            this.isDetectionActive = data.active;
            this.updateDetectionStatus(data.active ? 'active' : 'inactive');
            this.updateModelStatus(data.models_loaded);

            // If detection is active but video isn't streaming, start it
            if (data.active && !document.getElementById('localCam')?.src?.includes('/video_feed')) {
                this.startVideoStream();
            }

        } catch (error) {
            console.error('Status check failed:', error);
            this.updateDetectionStatus('error');
        }
    }

    async checkInitialDetectionStatus() {
        await this.checkDetectionStatus();
    }

    async checkForNewThreats() {
        try {
            const response = await fetch('/api/threats');
            const threats = await response.json();

            if (threats && threats.length > 0) {
                // Check for new threats since last check
                const newThreats = threats.filter(threat => {
                    const threatTime = new Date(threat.timestamp).getTime();
                    return threatTime > this.lastThreatCheck;
                });

                if (newThreats.length > 0) {
                    newThreats.forEach(threat => {
                        this.handleNewThreat(threat);
                    });

                    this.lastThreatCheck = Date.now();
                }
            }
        } catch (error) {
            console.error('Failed to check for new threats:', error);
        }
    }

    handleNewThreat(threat) {
        const description = threat.description || 'Unknown threat';
        const location = threat.location || 'Unknown location';
        const status = threat.status || 'Unknown status';

        // Add to recent detections
        this.addRecentDetection('AI Detection', `${description} at ${location}`);

        // Show urgent notification for high-priority threats
        if (description.includes('HIGH THREAT') || description.includes('Weapon')) {
            this.showNotification(`URGENT: ${description}`, 'error');
            this.blinkThreatIndicator();
        } else if (description.includes('WARNING') || description.includes('panic')) {
            this.showNotification(`WARNING: ${description}`, 'warning');
        }

        console.log(`New threat detected: ${description}`);
    }

    blinkThreatIndicator() {
        const statusElement = document.getElementById('detectionStatus');
        if (statusElement) {
            statusElement.classList.add('threat-level-danger');
            setTimeout(() => {
                statusElement.classList.remove('threat-level-danger');
            }, 5000);
        }
    }

    startThreatsMonitoring() {
        this.stopThreatsMonitoring(); // Clear existing interval
        this.lastThreatCheck = Date.now() - 10000; // Check for threats in last 10 seconds

        this.threatsCheckInterval = setInterval(() => {
            if (this.isDetectionActive) {
                this.checkForNewThreats();
            }
        }, 2000); // Check every 2 seconds when detection is active
    }

    stopThreatsMonitoring() {
        if (this.threatsCheckInterval) {
            clearInterval(this.threatsCheckInterval);
            this.threatsCheckInterval = null;
        }
    }

    updateDetectionStatus(status) {
        const statusElement = document.getElementById('detectionStatus');
        const statusBadge = document.getElementById('statusBadge');
        const statusText = document.getElementById('statusText');
        const startBtn = document.getElementById('startDetection') ||
                         document.querySelector('.btn-primary');
        const stopBtn = document.getElementById('stopDetection') ||
                        document.querySelector('.btn-secondary');

        if (statusElement) {
            // Remove existing status classes
            statusElement.classList.remove('state-success', 'state-error', 'state-warning');
        }

        if (statusBadge) {
            statusBadge.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'bg-secondary');
        }

        switch (status) {
            case 'active':
                if (statusElement) statusElement.classList.add('state-success');
                if (statusBadge) {
                    statusBadge.classList.add('bg-success');
                    statusBadge.textContent = 'LIVE';
                }
                if (statusText) statusText.textContent = 'AI Detection ACTIVE - Monitoring for threats...';
                if (startBtn) startBtn.disabled = true;
                if (stopBtn) stopBtn.disabled = false;
                break;

            case 'inactive':
                if (statusElement) statusElement.classList.add('state-warning');
                if (statusBadge) {
                    statusBadge.classList.add('bg-warning');
                    statusBadge.textContent = 'INACTIVE';
                }
                if (statusText) statusText.textContent = 'AI Detection is stopped';
                if (startBtn) startBtn.disabled = false;
                if (stopBtn) stopBtn.disabled = true;
                break;

            case 'error':
                if (statusElement) statusElement.classList.add('state-error');
                if (statusBadge) {
                    statusBadge.classList.add('bg-danger');
                    statusBadge.textContent = 'ERROR';
                }
                if (statusText) statusText.textContent = 'Detection system error';
                if (startBtn) startBtn.disabled = false;
                if (stopBtn) stopBtn.disabled = false;
                break;
        }
    }

    updateModelStatus(modelsLoaded) {
        const modelStatusElement = document.getElementById('modelStatus');
        if (!modelStatusElement) return;

        if (modelsLoaded) {
            modelStatusElement.innerHTML = '<span class="badge bg-success">AI Models Ready</span>';
        } else {
            modelStatusElement.innerHTML = '<span class="badge bg-danger">Models Not Loaded</span>';
        }
    }

    startStatusMonitoring() {
        this.stopStatusMonitoring(); // Clear existing interval
        this.detectionCheckInterval = setInterval(() => {
            this.checkDetectionStatus();
        }, 3000); // Check every 3 seconds
    }

    stopStatusMonitoring() {
        if (this.detectionCheckInterval) {
            clearInterval(this.detectionCheckInterval);
            this.detectionCheckInterval = null;
        }
    }

    setButtonLoading(buttonId, loading) {
        const button = document.getElementById(buttonId) ||
                      (buttonId === 'startDetection' ? document.querySelector('.btn-primary') : document.querySelector('.btn-secondary'));
        if (!button) return;

        if (loading) {
            button.classList.add('loading');
            button.disabled = true;
            const originalText = button.textContent;
            button.textContent = buttonId === 'startDetection' ? 'Starting...' : 'Stopping...';
            button.setAttribute('data-original-text', originalText);
        } else {
            button.classList.remove('loading');
            const originalText = button.getAttribute('data-original-text');
            if (originalText) {
                button.textContent = originalText;
                button.removeAttribute('data-original-text');
            }
        }
    }

    showNotification(message, type = 'info') {
        // Remove existing notifications
        const existingNotification = document.querySelector('.notification');
        if (existingNotification) {
            existingNotification.remove();
        }

        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification alert alert-${this.getBootstrapAlertClass(type)} alert-dismissible fade show`;
        notification.innerHTML = `
            <strong>${this.getNotificationTitle(type)}</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        // Add to page
        document.body.appendChild(notification);

        // Auto-remove after 5 seconds (longer for errors)
        const timeout = type === 'error' ? 8000 : 5000;
        setTimeout(() => {
            if (notification && notification.parentNode) {
                notification.remove();
            }
        }, timeout);
    }

    getBootstrapAlertClass(type) {
        const mapping = {
            'success': 'success',
            'error': 'danger',
            'warning': 'warning',
            'info': 'info'
        };
        return mapping[type] || 'info';
    }

    getNotificationTitle(type) {
        const titles = {
            'success': 'Success',
            'error': 'Error',
            'warning': 'Warning',
            'info': 'Info'
        };
        return titles[type] || 'Info';
    }

    addRecentDetection(source, description) {
        const timestamp = new Date().toLocaleTimeString();
        const detection = {
            timestamp,
            source,
            description,
            id: Date.now()
        };

        this.recentDetections.unshift(detection);

        // Keep only the most recent detections
        if (this.recentDetections.length > this.maxRecentDetections) {
            this.recentDetections = this.recentDetections.slice(0, this.maxRecentDetections);
        }

        this.updateRecentDetectionsList();
    }

    updateRecentDetectionsList() {
        const detectionList = document.getElementById('detectionList');
        if (!detectionList) return;

        if (this.recentDetections.length === 0) {
            detectionList.innerHTML = '<div class="list-group-item text-muted">No recent detections</div>';
            return;
        }

        detectionList.innerHTML = this.recentDetections.map(detection => `
            <div class="list-group-item list-group-item-action">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${detection.source}</h6>
                    <small>${detection.timestamp}</small>
                </div>
                <p class="mb-1">${detection.description}</p>
            </div>
        `).join('');
    }

    // Cleanup method
    destroy() {
        this.stopStatusMonitoring();
        this.stopThreatsMonitoring();
        this.stopVideoStream();

        console.log('AIDetectionController destroyed');
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing AI Detection Controller...');
    window.aiDetectionController = new AIDetectionController();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.aiDetectionController) {
        window.aiDetectionController.destroy();
    }
});