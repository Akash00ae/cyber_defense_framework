/**
 * Intelligent Cyber Defense Framework - Dashboard JavaScript
 * Handles real-time stats, charts (Chart.js), activity feed, logs, and config management.
 */

(function () {
    'use strict';

    // ─── Chart Instances ──────────────────────────────────────────────────────
    var monthlyChart = null;
    var distributionChart = null;
    var trendChart = null;
    var riskDistChart = null;
    var topIpsChart = null;

    // Chart.js global defaults
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(51, 65, 85, 0.5)';
    Chart.defaults.font.family = 'Poppins';

    // ─── Initialization ───────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', function () {
        initSidebarNav();
        refreshDashboard();
        loadConfig();

        // Auto-refresh every 10 seconds
        setInterval(refreshDashboard, 10000);
    });

    // ─── Sidebar Navigation ───────────────────────────────────────────────────
    function initSidebarNav() {
        var links = document.querySelectorAll('.sidebar-nav a[data-section]');
        links.forEach(function (link) {
            link.addEventListener('click', function (e) {
                e.preventDefault();
                var section = this.getAttribute('data-section');

                // Update active state
                links.forEach(function (l) { l.classList.remove('active'); });
                this.classList.add('active');

                // Show/hide sections
                var sections = ['overview', 'analytics', 'logs', 'config'];
                sections.forEach(function (s) {
                    var el = document.getElementById('section-' + s);
                    if (el) {
                        el.classList.toggle('hidden', s !== section);
                    }
                });

                // Load section-specific data
                if (section === 'analytics') loadAnalytics();
                if (section === 'logs') loadLogs();
                if (section === 'config') loadConfig();

                // Close mobile sidebar
                document.getElementById('sidebar').classList.remove('open');
            });
        });
    }

    // ─── Refresh Everything ───────────────────────────────────────────────────
    window.refreshDashboard = function () {
        loadStats();
        loadMonthlyChart();
        loadDistributionChart();
        loadTrendChart();
        loadActivityFeed();
    };

    // ─── Load Stats ───────────────────────────────────────────────────────────
    function loadStats() {
        fetch('/api/stats')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                animateValue('statTotal', data.total_requests);
                animateValue('statAbnormal', data.abnormal_attempts);
                animateValue('statNormal', data.normal_requests);
                animateValue('statActive', data.active_sessions);
                animateValue('statDecoy', data.decoy_interactions);
            })
            .catch(function () {});
    }

    function animateValue(elementId, target) {
        var el = document.getElementById(elementId);
        if (!el) return;
        var current = parseInt(el.textContent) || 0;
        if (current === target) return;

        var step = Math.ceil(Math.abs(target - current) / 20);
        var timer = setInterval(function () {
            if (current < target) {
                current = Math.min(current + step, target);
            } else {
                current = Math.max(current - step, target);
            }
            el.textContent = current.toLocaleString();
            if (current === target) clearInterval(timer);
        }, 30);
    }

    // ─── Monthly Activity Chart ───────────────────────────────────────────────
    function loadMonthlyChart() {
        fetch('/api/monthly_data')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var labels = data.map(function (d) { return d.month; });
                var abnormal = data.map(function (d) { return d.abnormal; });
                var normal = data.map(function (d) { return d.normal; });

                var ctx = document.getElementById('monthlyChart');
                if (!ctx) return;

                if (monthlyChart) monthlyChart.destroy();

                monthlyChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Abnormal',
                                data: abnormal,
                                backgroundColor: 'rgba(239, 68, 68, 0.7)',
                                borderRadius: 6
                            },
                            {
                                label: 'Normal',
                                data: normal,
                                backgroundColor: 'rgba(34, 197, 94, 0.7)',
                                borderRadius: 6
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'top', labels: { padding: 15, usePointStyle: true, pointStyle: 'circle' } }
                        },
                        scales: {
                            y: { beginAtZero: true, grid: { color: 'rgba(51,65,85,0.3)' } },
                            x: { grid: { display: false } }
                        }
                    }
                });
            })
            .catch(function () {});
    }

    // ─── Distribution Chart ───────────────────────────────────────────────────
    function loadDistributionChart() {
        fetch('/api/stats')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var ctx = document.getElementById('distributionChart');
                if (!ctx) return;

                if (distributionChart) distributionChart.destroy();

                distributionChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Normal', 'Abnormal'],
                        datasets: [{
                            data: [data.normal_requests || 0, data.abnormal_attempts || 0],
                            backgroundColor: ['rgba(34, 197, 94, 0.8)', 'rgba(239, 68, 68, 0.8)'],
                            borderColor: ['rgba(34, 197, 94, 1)', 'rgba(239, 68, 68, 1)'],
                            borderWidth: 2,
                            cutout: '65%'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true, pointStyle: 'circle' } }
                        }
                    }
                });
            })
            .catch(function () {});
    }

    // ─── 24-Hour Trend Chart ──────────────────────────────────────────────────
    function loadTrendChart() {
        fetch('/api/hourly_trend')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var labels = data.map(function (d) { return d.hour + ':00'; });
                var totals = data.map(function (d) { return d.total; });
                var abnormal = data.map(function (d) { return d.abnormal; });

                var ctx = document.getElementById('trendChart');
                if (!ctx) return;

                if (trendChart) trendChart.destroy();

                trendChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Total Requests',
                                data: totals,
                                borderColor: '#3b82f6',
                                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                fill: true,
                                tension: 0.4,
                                pointRadius: 3,
                                pointHoverRadius: 6
                            },
                            {
                                label: 'Abnormal',
                                data: abnormal,
                                borderColor: '#ef4444',
                                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                fill: true,
                                tension: 0.4,
                                pointRadius: 3,
                                pointHoverRadius: 6
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'top', labels: { padding: 15, usePointStyle: true, pointStyle: 'circle' } }
                        },
                        scales: {
                            y: { beginAtZero: true, grid: { color: 'rgba(51,65,85,0.3)' } },
                            x: { grid: { display: false } }
                        }
                    }
                });
            })
            .catch(function () {});
    }

    // ─── Activity Feed ────────────────────────────────────────────────────────
    function loadActivityFeed() {
        fetch('/api/logs?limit=20')
            .then(function (r) { return r.json(); })
            .then(function (logs) {
                var feed = document.getElementById('activityFeed');
                if (!feed) return;

                if (logs.length === 0) {
                    feed.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;text-align:center;padding:2rem;">No activity recorded yet.</p>';
                    return;
                }

                var html = '';
                logs.forEach(function (log) {
                    var time = formatTimestamp(log.timestamp);
                    var inputPreview = escapeHtml(log.user_input).substring(0, 60);
                    if (log.user_input.length > 60) inputPreview += '...';

                    html += '<div class="activity-item">' +
                        '<div class="activity-dot ' + log.status + '"></div>' +
                        '<div class="activity-info">' +
                            '<div class="text"><strong>' + log.status.toUpperCase() + '</strong> — "' + inputPreview + '" ' +
                            '<span class="risk-score-badge ' + riskClass(log.risk_score) + '">' + log.risk_score + '</span></div>' +
                            '<div class="time">' + time + ' • IP: ' + escapeHtml(log.ip_address) + '</div>' +
                        '</div>' +
                    '</div>';
                });

                feed.innerHTML = html;

                // Update timestamp
                var lastUpdate = document.getElementById('lastUpdate');
                if (lastUpdate) {
                    lastUpdate.textContent = 'Updated: ' + new Date().toLocaleTimeString();
                }
            })
            .catch(function () {});
    }

    // ─── Analytics Section ────────────────────────────────────────────────────
    function loadAnalytics() {
        loadRiskDistribution();
        loadTopIps();
        loadInsights();
    }

    function loadRiskDistribution() {
        fetch('/api/risk_distribution')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var labels = data.map(function (d) { return d.category; });
                var counts = data.map(function (d) { return d.count; });

                var ctx = document.getElementById('riskDistChart');
                if (!ctx) return;

                if (riskDistChart) riskDistChart.destroy();

                riskDistChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Requests',
                            data: counts,
                            backgroundColor: [
                                'rgba(34, 197, 94, 0.7)',
                                'rgba(245, 158, 11, 0.7)',
                                'rgba(239, 68, 68, 0.7)',
                                'rgba(139, 92, 246, 0.7)'
                            ],
                            borderRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { beginAtZero: true, grid: { color: 'rgba(51,65,85,0.3)' } },
                            y: { grid: { display: false } }
                        }
                    }
                });
            })
            .catch(function () {});
    }

    function loadTopIps() {
        fetch('/api/top_ips')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var labels = data.map(function (d) { return d.ip_address; });
                var requests = data.map(function (d) { return d.request_count; });
                var abnormal = data.map(function (d) { return d.abnormal_count; });

                var ctx = document.getElementById('topIpsChart');
                if (!ctx) return;

                if (topIpsChart) topIpsChart.destroy();

                topIpsChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Total Requests',
                                data: requests,
                                backgroundColor: 'rgba(59, 130, 246, 0.7)',
                                borderRadius: 6
                            },
                            {
                                label: 'Abnormal',
                                data: abnormal,
                                backgroundColor: 'rgba(239, 68, 68, 0.7)',
                                borderRadius: 6
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { position: 'top', labels: { padding: 15, usePointStyle: true, pointStyle: 'circle' } } },
                        scales: {
                            y: { beginAtZero: true, grid: { color: 'rgba(51,65,85,0.3)' } },
                            x: { grid: { display: false } }
                        }
                    }
                });
            })
            .catch(function () {});
    }

    function loadInsights() {
        fetch('/api/stats')
            .then(function (r) { return r.json(); })
            .then(function (stats) {
                var panel = document.getElementById('insightsPanel');
                if (!panel) return;

                var total = stats.total_requests || 0;
                var abnormal = stats.abnormal_attempts || 0;
                var rate = total > 0 ? ((abnormal / total) * 100).toFixed(1) : 0;
                var decoy = stats.decoy_interactions || 0;

                var html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;">';

                html += '<div style="background:var(--bg-primary);border-radius:10px;padding:1.25rem;">' +
                    '<div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">Threat Rate</div>' +
                    '<div style="font-size:1.5rem;font-weight:700;margin:0.25rem 0;color:' + (rate > 30 ? 'var(--alert)' : 'var(--success)') + ';">' + rate + '%</div>' +
                    '<div style="font-size:0.75rem;color:var(--text-secondary);">' + abnormal + ' abnormal out of ' + total + ' total requests</div>' +
                '</div>';

                html += '<div style="background:var(--bg-primary);border-radius:10px;padding:1.25rem;">' +
                    '<div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">Decoy Engagement</div>' +
                    '<div style="font-size:1.5rem;font-weight:700;margin:0.25rem 0;color:#8b5cf6;">' + decoy + '</div>' +
                    '<div style="font-size:0.75rem;color:var(--text-secondary);">Total interactions in deception environments</div>' +
                '</div>';

                html += '<div style="background:var(--bg-primary);border-radius:10px;padding:1.25rem;">' +
                    '<div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">Active Monitoring</div>' +
                    '<div style="font-size:1.5rem;font-weight:700;margin:0.25rem 0;color:var(--success);">' + stats.active_sessions + '</div>' +
                    '<div style="font-size:0.75rem;color:var(--text-secondary);">Unique IPs active in last 15 minutes</div>' +
                '</div>';

                html += '</div>';
                panel.innerHTML = html;
            })
            .catch(function () {});
    }

    // ─── Logs Table ───────────────────────────────────────────────────────────
    function loadLogs() {
        fetch('/api/logs?limit=100')
            .then(function (r) { return r.json(); })
            .then(function (logs) {
                var tbody = document.getElementById('logsTableBody');
                if (!tbody) return;

                if (logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:2rem;">No logs recorded yet.</td></tr>';
                    return;
                }

                var html = '';
                logs.forEach(function (log) {
                    var inputPreview = escapeHtml(log.user_input).substring(0, 40);
                    if (log.user_input.length > 40) inputPreview += '...';

                    html += '<tr>' +
                        '<td>' + log.id + '</td>' +
                        '<td>' + formatTimestamp(log.timestamp) + '</td>' +
                        '<td class="input-cell" title="' + escapeHtml(log.user_input) + '">' + inputPreview + '</td>' +
                        '<td><span class="risk-score-badge ' + riskClass(log.risk_score) + '">' + log.risk_score + '</span></td>' +
                        '<td><span class="status-badge ' + log.status + '">' + log.status + '</span></td>' +
                        '<td>' + escapeHtml(log.ip_address) + '</td>' +
                        '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(log.details) + '">' + escapeHtml(log.details) + '</td>' +
                    '</tr>';
                });

                tbody.innerHTML = html;
            })
            .catch(function () {});
    }

    // ─── Configuration ────────────────────────────────────────────────────────
    function loadConfig() {
        fetch('/api/config')
            .then(function (r) { return r.json(); })
            .then(function (config) {
                var grid = document.getElementById('configGrid');
                if (!grid) return;

                var labels = {
                    'risk_threshold': 'Risk Threshold',
                    'long_keyword_score': 'Long Keyword Score',
                    'special_chars_score': 'Special Chars Score',
                    'repeated_requests_score': 'Repeated Requests Score',
                    'sql_injection_score': 'SQL Injection Score',
                    'long_keyword_length': 'Long Keyword Length (chars)',
                    'repeat_window_seconds': 'Repeat Window (seconds)',
                    'repeat_count_limit': 'Repeat Count Limit'
                };

                var html = '';
                Object.keys(labels).forEach(function (key) {
                    if (config[key] !== undefined) {
                        html += '<div class="config-item">' +
                            '<label for="cfg_' + key + '">' + labels[key] + '</label>' +
                            '<input type="number" id="cfg_' + key + '" data-key="' + key + '" value="' + config[key] + '" min="0">' +
                        '</div>';
                    }
                });

                grid.innerHTML = html;
            })
            .catch(function () {});
    }

    window.saveConfig = function () {
        var inputs = document.querySelectorAll('#configGrid input');
        var config = {};
        inputs.forEach(function (input) {
            config[input.getAttribute('data-key')] = parseInt(input.value) || 0;
        });

        fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var status = document.getElementById('configStatus');
            if (status) {
                status.innerHTML = '<span style="color:var(--success);">✅ Configuration saved successfully!</span>';
                setTimeout(function () { status.innerHTML = ''; }, 3000);
            }
        })
        .catch(function () {
            var status = document.getElementById('configStatus');
            if (status) {
                status.innerHTML = '<span style="color:var(--alert);">❌ Failed to save configuration.</span>';
            }
        });
    };

    // ─── Helpers ──────────────────────────────────────────────────────────────
    function formatTimestamp(ts) {
        if (!ts) return '—';
        var d = new Date(ts);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
    }

    function riskClass(score) {
        if (score <= 2) return 'low';
        if (score <= 5) return 'medium';
        return 'high';
    }

    function escapeHtml(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(text));
        return div.innerHTML;
    }

})();
