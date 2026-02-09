// Enhanced JavaScript for ML Dashboard with Alert System
document.addEventListener('DOMContentLoaded', function() {
    AOS.init({ duration: 1000, easing: 'ease-in-out', once: true, offset: 100 });
    initNavbarScroll();
    initSmoothScrolling();
    initLoadingStates();
    initTooltips();
    loadIncidents();
});

function initNavbarScroll() {
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', function() {
        navbar.classList.toggle('scrolled', window.scrollY > 100);
    });
}

function initSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });
}

function initLoadingStates() {
    document.querySelectorAll('.chart-overlay').forEach(overlay => {
        overlay.style.display = 'flex';
    });
}

function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(el => new bootstrap.Tooltip(el));
}

// Toggle Alert Panel
function toggleAlertPanel() {
    const panel = document.getElementById('alertPanel');
    panel.classList.toggle('show');
}

// Main ML Analysis Function
function runML() {
    const runButton = document.getElementById('runButton');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const buttonText = runButton.querySelector('span');
    
    setButtonLoading(runButton, loadingSpinner, buttonText, true);
    showLoadingOverlays();
    resetAccuracyCards();
    
    const startTime = performance.now();
    
    fetch('/run-ml', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ timestamp: new Date().toISOString() })
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    })
    .then(data => {
        const processingTime = ((performance.now() - startTime) / 1000).toFixed(2);
        
        console.log(`ML processing completed in ${processingTime}s`);
        
        updateAccuracyCards(data.accuracies);
        updateCharts(data);
        updateThreatCount(data.alert_data.total_malicious);
        
        // Handle Alert System
        if (data.alert_data.alert_triggered) {
            showAlertPanel(data.alert_data);
            updateNotificationBadge(data.alert_data.total_malicious);
        }
        
        // Load and display incidents
        loadIncidents();
        
        showSuccessNotification(`Analysis completed in ${processingTime}s - ${data.alert_data.total_malicious} threats detected`);
        setButtonLoading(runButton, loadingSpinner, buttonText, false);
        setTimeout(() => hideLoadingOverlays(), 500);
    })
    .catch(error => {
        console.error('Error running ML analysis:', error);
        showErrorNotification('Failed to run analysis. Please try again.');
        setButtonLoading(runButton, loadingSpinner, buttonText, false);
        hideLoadingOverlays();
        runButton.classList.add('error-shake');
        setTimeout(() => runButton.classList.remove('error-shake'), 500);
    });
}

// Show Alert Panel with Data
function showAlertPanel(alertData) {
    const alertContent = document.getElementById('alertContent');
    const panel = document.getElementById('alertPanel');
    
    let attackList = '';
    for (const [attack, count] of Object.entries(alertData.attack_distribution)) {
        attackList += `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 bg-light rounded">
                <span class="attack-badge attack-${attack}">${attack.replace('_', ' ').toUpperCase()}</span>
                <span class="badge bg-danger">${count} nodes</span>
            </div>
        `;
    }
    
    const nodesList = alertData.malicious_nodes.slice(0, 10).join(', ');
    
    alertContent.innerHTML = `
        <div class="alert alert-danger border-0 shadow-sm mb-3">
            <div class="d-flex align-items-center mb-2">
                <i class="bi bi-exclamation-triangle-fill fs-4 me-2"></i>
                <h5 class="mb-0">⚠️ ALERT: ${alertData.total_malicious} Malicious Nodes Detected</h5>
            </div>
            <p class="mb-2"><strong>Time:</strong> ${new Date().toLocaleTimeString()}</p>
            <p class="mb-0"><strong>Affected Nodes:</strong> ${nodesList}${alertData.malicious_nodes.length > 10 ? '...' : ''}</p>
        </div>
        
        <div class="mb-3">
            <h6 class="fw-bold mb-3">Attack Type Breakdown</h6>
            ${attackList}
        </div>
        
        <div class="mb-3">
            <h6 class="fw-bold mb-3">Top Recent Incidents</h6>
            ${alertData.top_incidents.map(incident => `
                <div class="incident-card p-2 mb-2 rounded">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <strong>Node ${incident.node_id}</strong>
                            <span class="attack-badge attack-${incident.attack_type} ms-2">${incident.attack_type}</span>
                        </div>
                        <small class="text-muted">${incident.confidence}</small>
                    </div>
                    <small class="text-muted">${incident.timestamp}</small>
                </div>
            `).join('')}
        </div>
        
        <button class="btn btn-danger w-100" onclick="scrollToIncidents()">
            <i class="bi bi-journal-text me-2"></i>View Full Incident Log
        </button>
    `;
    
    panel.classList.add('show');
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
        panel.classList.remove('show');
    }, 10000);
}

// Update Notification Badge
function updateNotificationBadge(count) {
    const badge = document.getElementById('notificationCount');
    if (count > 0) {
        badge.textContent = count;
        badge.classList.remove('d-none');
    } else {
        badge.classList.add('d-none');
    }
}

// Load and Display Incidents
function loadIncidents() {
    fetch('/get-incidents')
        .then(response => response.json())
        .then(data => {
            const incidentLog = document.getElementById('incidentLog');
            
            if (data.incidents.length === 0) {
                incidentLog.innerHTML = '<p class="text-muted text-center">No incidents recorded yet.</p>';
                return;
            }
            
            const incidentsHtml = data.incidents.reverse().map(incident => `
                <div class="incident-card p-3 mb-3 rounded shadow-sm">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div>
                            <h6 class="mb-1">
                                <i class="bi bi-shield-exclamation text-danger me-2"></i>
                                Node ${incident.node_id}
                                <span class="attack-badge attack-${incident.attack_type} ms-2">
                                    ${incident.attack_type.replace('_', ' ').toUpperCase()}
                                </span>
                            </h6>
                            <small class="text-muted">
                                <i class="bi bi-clock me-1"></i>${incident.timestamp}
                            </small>
                        </div>
                        <div class="text-end">
                            <div class="badge bg-danger">${incident.confidence}</div>
                        </div>
                    </div>
                    <div class="row g-2 mt-2">
                        <div class="col-6">
                            <small class="text-muted">PDR:</small>
                            <strong class="d-block">${incident.features.pdr.toFixed(3)}</strong>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Drop Rate:</small>
                            <strong class="d-block">${incident.features.packet_drop_rate.toFixed(3)}</strong>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Throughput:</small>
                            <strong class="d-block">${incident.features.throughput.toFixed(1)} Mbps</strong>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Bandwidth:</small>
                            <strong class="d-block">${incident.features.bandwidth.toFixed(1)} Mbps</strong>
                        </div>
                    </div>
                </div>
            `).join('');
            
            incidentLog.innerHTML = incidentsHtml;
        })
        .catch(error => {
            console.error('Error loading incidents:', error);
        });
}

// Clear Incidents
function clearIncidents() {
    if (!confirm('Are you sure you want to clear all incident logs?')) return;
    
    fetch('/clear-incidents', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            showSuccessNotification(data.message);
            loadIncidents();
            updateNotificationBadge(0);
        })
        .catch(error => {
            showErrorNotification('Failed to clear incidents');
        });
}

// Scroll to Incidents Section
function scrollToIncidents() {
    const section = document.getElementById('incidents');
    if (section) {
        section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        toggleAlertPanel(); // Close alert panel
    }
}

function setButtonLoading(button, spinner, textElement, isLoading) {
    if (isLoading) {
        button.disabled = true;
        spinner.classList.remove('d-none');
        textElement.textContent = 'Analyzing...';
    } else {
        button.disabled = false;
        spinner.classList.add('d-none');
        textElement.textContent = 'Run Analysis';
        button.classList.add('success-animation');
        setTimeout(() => button.classList.remove('success-animation'), 600);
    }
}

function showLoadingOverlays() {
    document.querySelectorAll('.chart-overlay').forEach(overlay => {
        overlay.classList.remove('hidden');
        overlay.style.display = 'flex';
    });
}

function hideLoadingOverlays() {
    document.querySelectorAll('.chart-overlay').forEach(overlay => {
        overlay.classList.add('hidden');
        setTimeout(() => overlay.style.display = 'none', 500);
    });
}

function resetAccuracyCards() {
    ['svm', 'rf', 'xgb', 'bpnn'].forEach(model => {
        const el = document.getElementById(`${model}-accuracy`);
        const bar = document.getElementById(`${model}-progress`);
        if (el) el.textContent = '--';
        if (bar) bar.style.width = '0%';
    });
}

function updateAccuracyCards(accuracies) {
    const modelMapping = {
        'SVM': { id: 'svm', color: 'primary' },
        'RandomForest': { id: 'rf', color: 'success' },
        'XGBoost': { id: 'xgb', color: 'warning' },
        'BPNN': { id: 'bpnn', color: 'info' }
    };
    
    Object.entries(accuracies).forEach(([model, accuracy], index) => {
        const mapping = modelMapping[model];
        if (!mapping) return;
        setTimeout(() => updateSingleAccuracyCard(mapping.id, accuracy), index * 200);
    });
}

function updateSingleAccuracyCard(modelId, accuracy) {
    const accuracyEl = document.getElementById(`${modelId}-accuracy`);
    const progressEl = document.getElementById(`${modelId}-progress`);
    const card = document.querySelector(`[data-model="${modelId}"]`);
    
    if (accuracyEl && progressEl) {
        const value = parseFloat(accuracy.replace('%', ''));
        animateCounter(accuracyEl, 0, value, 1500);
        setTimeout(() => progressEl.style.width = `${value}%`, 300);
        
        if (card) {
            card.classList.add('success-animation');
            setTimeout(() => card.classList.remove('success-animation'), 600);
        }
    }
}

function animateCounter(element, start, end, duration) {
    const startTime = performance.now();
    const range = end - start;
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeProgress = 1 - Math.pow(1 - progress, 3);
        const current = start + (range * easeProgress);
        
        element.textContent = current.toFixed(1);
        
        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = end.toFixed(1);
        }
    }
    
    requestAnimationFrame(update);
}

function updateCharts(data) {
    const charts = [
        { id: 'throughput_img', data: 'throughput_img' },
        { id: 'confusion_matrix_img', data: 'confusion_matrix_img' },
        { id: 'final_heatmap_img', data: 'final_heatmap_img' },
        { id: 'accuracy_bar_img', data: 'accuracy_bar_img' }
    ];
    
    charts.forEach((chart, index) => {
        setTimeout(() => updateSingleChart(chart.id, data[chart.data]), index * 300);
    });
    
    // Handle attack distribution chart
    if (data.attack_distribution_img) {
        document.getElementById('attackDistributionCard').style.display = 'block';
        updateSingleChart('attack_distribution_img', data.attack_distribution_img);
    }
}

function updateSingleChart(elementId, imageData) {
    const img = document.getElementById(elementId);
    if (img && imageData) {
        const newImg = new Image();
        newImg.onload = function() {
            img.style.opacity = '0';
            img.src = 'data:image/png;base64,' + imageData;
            setTimeout(() => {
                img.style.transition = 'opacity 0.5s ease';
                img.style.opacity = '1';
            }, 100);
        };
        newImg.src = 'data:image/png;base64,' + imageData;
    }
}

function updateThreatCount(count) {
    const el = document.getElementById('threatsCount');
    if (el) {
        el.textContent = count;
        el.parentElement.parentElement.classList.add('status-online');
    }
}

function showSuccessNotification(message) {
    createNotification(message, 'success', 'bi-check-circle');
}

function showErrorNotification(message) {
    createNotification(message, 'danger', 'bi-exclamation-triangle');
}

function createNotification(message, type, icon) {
    const container = getOrCreateToastContainer();
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body d-flex align-items-center">
                <i class="bi ${icon} me-2"></i>${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    container.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast, { autohide: true, delay: 5000 });
    bsToast.show();
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

function getOrCreateToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }
    return container;
}

function scrollToResults() {
    document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Keyboard Shortcuts
document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        runML();
    }
    if (e.key === 'Escape') {
        const panel = document.getElementById('alertPanel');
        if (panel.classList.contains('show')) {
            toggleAlertPanel();
        } else {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }
});

// Auto-refresh incidents every 30 seconds
setInterval(() => {
    const incidentLog = document.getElementById('incidentLog');
    if (incidentLog && !incidentLog.querySelector('.text-center')) {
        loadIncidents();
    }
}, 30000);