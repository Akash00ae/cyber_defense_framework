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
            if (data.status === 'normal') {
                loaderOverlay.classList.remove('active');
                submitBtn.disabled = false;
                if (data.redirect_url) window.open(data.redirect_url, '_blank');
            } else {
                if (data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else {
                    loaderOverlay.classList.remove('active');
                    submitBtn.disabled = false;
                }
            }
        })
        .catch(function (err) {
            loaderOverlay.classList.remove('active');
            submitBtn.disabled = false;
        });
    }

    // Keyboard shortcut: Enter to submit
    keywordInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            analyzeRequest();
        }
    });
})();
