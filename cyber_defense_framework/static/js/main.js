/**
 * Intelligent Cyber Defense Framework - Landing Page JavaScript
 * Handles keyword submission, AJAX analysis, loading indicators, and result display.
 */

(function () {
    'use strict';

    var searchForm = document.getElementById('searchForm');
    var keywordInput = document.getElementById('keywordInput');
    var submitBtn = document.getElementById('submitBtn');
    var loaderOverlay = document.getElementById('loaderOverlay');
    var resultToast = document.getElementById('resultToast');
    var toastIcon = document.getElementById('toastIcon');
    var toastTitle = document.getElementById('toastTitle');
    var toastBody = document.getElementById('toastBody');
    var toastScore = document.getElementById('toastScore');

    // Submit handler
    searchForm.addEventListener('submit', function (e) {
        e.preventDefault();
        analyzeRequest();
    });

    submitBtn.addEventListener('click', function () {
        analyzeRequest();
    });

    function analyzeRequest() {
        var keyword = keywordInput.value.trim();
        if (!keyword) {
            keywordInput.focus();
            return;
        }

        // Show loader
        loaderOverlay.classList.add('active');
        submitBtn.disabled = true;
        hideToast();

        // Send AJAX request
        fetch('/analyze_request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ keyword: keyword })
        })
        .then(function (response) {
            if (!response.ok) throw new Error('Request failed');
            return response.json();
        })
        .then(function (data) {
            // Hide loader
            loaderOverlay.classList.remove('active');
            submitBtn.disabled = false;

            // Show result toast
            showToast(data);

            // Redirect after a brief delay
            setTimeout(function () {
                if (data.redirect_url) {
                    window.open(data.redirect_url, '_blank');
                }
            }, 1500);
        })
        .catch(function (err) {
            loaderOverlay.classList.remove('active');
            submitBtn.disabled = false;
            showErrorToast('Analysis failed. Please try again.');
        });
    }

    function showToast(data) {
        resultToast.className = 'result-toast active ' + data.status;

        if (data.status === 'normal') {
            toastIcon.textContent = '✅';
            toastTitle.textContent = 'Access Granted';
            toastBody.textContent = 'Request classified as safe. Redirecting to resource...';
            toastScore.className = 'toast-score low';
        } else {
            toastIcon.textContent = '⚠️';
            toastTitle.textContent = 'Threat Detected';
            toastBody.textContent = data.details || 'Suspicious behavior identified.';
            toastScore.className = 'toast-score high';
        }

        toastScore.textContent = 'Risk Score: ' + data.risk_score + ' / Threshold: ' + data.threshold;

        // Auto-hide after 8 seconds
        setTimeout(hideToast, 8000);
    }

    function showErrorToast(message) {
        resultToast.className = 'result-toast active abnormal';
        toastIcon.textContent = '❌';
        toastTitle.textContent = 'Error';
        toastBody.textContent = message;
        toastScore.style.display = 'none';
        setTimeout(hideToast, 5000);
    }

    function hideToast() {
        resultToast.classList.remove('active');
        toastScore.style.display = '';
    }

    // Keyboard shortcut: Enter to submit
    keywordInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            analyzeRequest();
        }
    });
})();
