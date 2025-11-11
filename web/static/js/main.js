// Main JavaScript for OSINT Tool Web Interface

let currentScanId = null;
let statusCheckInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeForm();
    loadRecentScans();
});

// Initialize scan form
function initializeForm() {
    const form = document.getElementById('scanForm');
    form.addEventListener('submit', handleScanSubmit);
}

// Handle scan form submission
async function handleScanSubmit(e) {
    e.preventDefault();

    const form = e.target;
    const formData = new FormData(form);

    // Get target
    const target = formData.get('target');

    if (!target) {
        alert('대상을 입력해주세요');
        return;
    }

    // Get selected modules
    const modules = {
        dns_enumeration: formData.has('dns_enumeration'),
        whois_lookup: formData.has('whois_lookup'),
        subdomain_enumeration: formData.has('subdomain_enumeration'),
        port_scanning: formData.has('port_scanning'),
        web_technology_detection: formData.has('web_technology_detection')
    };

    // Disable form
    const submitBtn = document.getElementById('startScanBtn');
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-text').style.display = 'none';
    submitBtn.querySelector('.btn-loader').style.display = 'flex';

    try {
        // Start scan
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                ...modules
            })
        });

        const data = await response.json();

        if (response.ok) {
            currentScanId = data.scan_id;

            // Show progress section
            document.getElementById('progressSection').style.display = 'block';
            document.getElementById('scanTarget').textContent = target;
            document.getElementById('scanId').textContent = data.scan_id;

            // Scroll to progress section
            document.getElementById('progressSection').scrollIntoView({ behavior: 'smooth' });

            // Start status polling
            startStatusPolling();
        } else {
            alert('스캔 시작 실패: ' + (data.error || '알 수 없는 오류'));
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        alert('스캔 시작 중 오류가 발생했습니다: ' + error.message);
    } finally {
        // Re-enable form
        submitBtn.disabled = false;
        submitBtn.querySelector('.btn-text').style.display = 'inline';
        submitBtn.querySelector('.btn-loader').style.display = 'none';
    }
}

// Start polling for scan status
function startStatusPolling() {
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
    }

    // Poll every 1 second
    statusCheckInterval = setInterval(checkScanStatus, 1000);

    // Check immediately
    checkScanStatus();
}

// Check scan status
async function checkScanStatus() {
    if (!currentScanId) return;

    try {
        const response = await fetch(`/api/scan/${currentScanId}/status`);
        const data = await response.json();

        if (response.ok) {
            updateScanProgress(data);

            // Stop polling if scan is complete or failed
            if (data.status === 'completed' || data.status === 'failed') {
                clearInterval(statusCheckInterval);
                handleScanComplete(data);
            }
        } else {
            console.error('Failed to get scan status:', data.error);
        }
    } catch (error) {
        console.error('Error checking scan status:', error);
    }
}

// Update scan progress UI
function updateScanProgress(scan) {
    // Update status badge
    const statusElement = document.getElementById('scanStatus');
    const statusText = {
        'initializing': '초기화 중',
        'running': '실행 중',
        'completed': '완료',
        'failed': '실패'
    }[scan.status] || scan.status;

    const statusClass = {
        'initializing': 'status-running',
        'running': 'status-running',
        'completed': 'status-completed',
        'failed': 'status-failed'
    }[scan.status] || 'status-running';

    statusElement.innerHTML = `<span class="status-badge ${statusClass}">${statusText}</span>`;

    // Update progress bar
    const progress = scan.progress || 0;
    document.getElementById('progressFill').style.width = `${progress}%`;
    document.getElementById('progressText').textContent = `${progress}%`;

    // Update logs
    if (scan.logs && scan.logs.length > 0) {
        updateLogs(scan.logs);
    }
}

// Update logs display
function updateLogs(logs) {
    const logsContainer = document.getElementById('logs');
    logsContainer.innerHTML = '';

    logs.forEach(log => {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-${log.level}`;

        const logTime = document.createElement('span');
        logTime.className = 'log-time';
        logTime.textContent = log.timestamp;

        const logMessage = document.createElement('span');
        logMessage.className = 'log-message';
        logMessage.textContent = log.message;

        logEntry.appendChild(logTime);
        logEntry.appendChild(logMessage);
        logsContainer.appendChild(logEntry);
    });

    // Scroll to bottom
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

// Handle scan completion
function handleScanComplete(scan) {
    if (scan.status === 'completed') {
        // Show action buttons
        const actionButtons = document.getElementById('actionButtons');
        actionButtons.style.display = 'flex';

        // Set up button handlers
        document.getElementById('viewResultsBtn').onclick = () => {
            window.location.href = `/results/${currentScanId}`;
        };

        document.getElementById('downloadJsonBtn').onclick = () => {
            downloadReport('json');
        };

        document.getElementById('downloadHtmlBtn').onclick = () => {
            downloadReport('html');
        };

        document.getElementById('newScanBtn').onclick = () => {
            window.location.reload();
        };

        // Reload recent scans
        loadRecentScans();
    } else if (scan.status === 'failed') {
        alert('스캔이 실패했습니다: ' + (scan.error || '알 수 없는 오류'));
    }
}

// Download report
function downloadReport(format) {
    if (!currentScanId) return;

    const url = `/api/scan/${currentScanId}/download/${format}`;
    window.open(url, '_blank');
}

// Load recent scans
async function loadRecentScans() {
    try {
        const response = await fetch('/api/scans');
        const scans = await response.json();

        const scansList = document.getElementById('scansList');

        if (scans.length === 0) {
            scansList.innerHTML = '<div class="empty-state"><p>아직 스캔 기록이 없습니다</p></div>';
            return;
        }

        scansList.innerHTML = '';

        scans.forEach(scan => {
            const scanItem = createScanItem(scan);
            scansList.appendChild(scanItem);
        });
    } catch (error) {
        console.error('Error loading recent scans:', error);
    }
}

// Create scan item element
function createScanItem(scan) {
    const item = document.createElement('div');
    item.className = 'scan-item';

    const statusText = {
        'completed': '완료',
        'running': '실행 중',
        'failed': '실패'
    }[scan.status] || scan.status;

    const statusClass = {
        'completed': 'status-completed',
        'running': 'status-running',
        'failed': 'status-failed'
    }[scan.status] || 'status-running';

    const createdAt = new Date(scan.created_at).toLocaleString('ko-KR');

    item.innerHTML = `
        <div class="scan-item-info">
            <h4>${scan.target}</h4>
            <p>
                <span class="status-badge ${statusClass}">${statusText}</span>
                · ${createdAt}
            </p>
        </div>
        <div class="scan-item-actions">
            ${scan.status === 'completed' ?
                `<button class="btn btn-sm btn-primary" onclick="viewScanResults('${scan.id}')">결과 보기</button>` :
                `<button class="btn btn-sm btn-outline" disabled>처리 중</button>`
            }
        </div>
    `;

    return item;
}

// View scan results
function viewScanResults(scanId) {
    window.location.href = `/results/${scanId}`;
}

// Helper function to format date
function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString('ko-KR');
}
