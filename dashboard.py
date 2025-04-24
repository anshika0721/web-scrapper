#!/usr/bin/env python3
"""
Web dashboard for viewing vulnerability scan results
"""

import json
import os
from typing import Dict, List, Optional

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Global variable to store scan results
scan_results = None

@app.route('/')
def index():
    """Render main dashboard page"""
    return render_template('index.html')

@app.route('/api/results', methods=['GET'])
def get_results():
    """Get scan results"""
    if scan_results is None:
        return jsonify({"error": "No scan results available"}), 404
    return jsonify(scan_results)

@app.route('/api/results', methods=['POST'])
def update_results():
    """Update scan results"""
    global scan_results
    try:
        scan_results = request.json
        return jsonify({"message": "Results updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/filter', methods=['GET'])
def filter_results():
    """Filter scan results"""
    if scan_results is None:
        return jsonify({"error": "No scan results available"}), 404
    
    # Get filter parameters
    severity = request.args.get('severity')
    vuln_type = request.args.get('type')
    url = request.args.get('url')
    
    # Filter vulnerabilities
    filtered_vulns = scan_results.get('vulnerabilities', [])
    
    if severity:
        filtered_vulns = [v for v in filtered_vulns if v.get('severity', '').lower() == severity.lower()]
    
    if vuln_type:
        filtered_vulns = [v for v in filtered_vulns if v.get('type', '').lower() == vuln_type.lower()]
    
    if url:
        filtered_vulns = [v for v in filtered_vulns if url.lower() in v.get('url', '').lower()]
    
    return jsonify({
        "vulnerabilities": filtered_vulns,
        "total": len(filtered_vulns)
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get scan statistics"""
    if scan_results is None:
        return jsonify({"error": "No scan results available"}), 404
    
    # Calculate statistics
    total_vulns = len(scan_results.get('vulnerabilities', []))
    severity_counts = {}
    type_counts = {}
    
    for vuln in scan_results.get('vulnerabilities', []):
        severity = vuln.get('severity', 'unknown')
        vuln_type = vuln.get('type', 'unknown')
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
    
    return jsonify({
        "total_vulnerabilities": total_vulns,
        "severity_distribution": severity_counts,
        "type_distribution": type_counts
    })

def create_app():
    """Create and configure Flask application"""
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create index.html template
    with open('templates/index.html', 'w') as f:
        f.write("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Vulnerability Scanner Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
            <style>
                .vuln-card { margin-bottom: 20px; }
                .severity-critical { border-left: 5px solid #dc3545; }
                .severity-high { border-left: 5px solid #fd7e14; }
                .severity-medium { border-left: 5px solid #ffc107; }
                .severity-low { border-left: 5px solid #28a745; }
                .severity-info { border-left: 5px solid #17a2b8; }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="#">Web Vulnerability Scanner Dashboard</a>
                </div>
            </nav>
            
            <div class="container mt-4">
                <div class="row">
                    <div class="col-md-3">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Filters</h5>
                            </div>
                            <div class="card-body">
                                <form id="filterForm">
                                    <div class="mb-3">
                                        <label class="form-label">Severity</label>
                                        <select class="form-select" id="severityFilter">
                                            <option value="">All</option>
                                            <option value="critical">Critical</option>
                                            <option value="high">High</option>
                                            <option value="medium">Medium</option>
                                            <option value="low">Low</option>
                                            <option value="info">Info</option>
                                        </select>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Type</label>
                                        <select class="form-select" id="typeFilter">
                                            <option value="">All</option>
                                        </select>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">URL</label>
                                        <input type="text" class="form-control" id="urlFilter" placeholder="Filter by URL">
                                    </div>
                                    <button type="submit" class="btn btn-primary">Apply Filters</button>
                                </form>
                            </div>
                        </div>
                        
                        <div class="card mt-4">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Statistics</h5>
                            </div>
                            <div class="card-body">
                                <div id="stats"></div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-9">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Vulnerabilities</h5>
                            </div>
                            <div class="card-body">
                                <div id="vulnList"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script>
                // Global variables
                let scanResults = null;
                
                // Fetch scan results
                async function fetchResults() {
                    try {
                        const response = await fetch('/api/results');
                        scanResults = await response.json();
                        updateDashboard();
                    } catch (error) {
                        console.error('Error fetching results:', error);
                    }
                }
                
                // Update dashboard
                function updateDashboard() {
                    updateVulnList();
                    updateStats();
                    updateTypeFilter();
                }
                
                // Update vulnerability list
                function updateVulnList(filtered = false) {
                    const vulnList = document.getElementById('vulnList');
                    const vulns = filtered ? scanResults.filtered_vulnerabilities : scanResults.vulnerabilities;
                    
                    vulnList.innerHTML = vulns.map(vuln => `
                        <div class="card vuln-card severity-${vuln.severity.toLowerCase()}">
                            <div class="card-body">
                                <h5 class="card-title">${vuln.type}</h5>
                                <h6 class="card-subtitle mb-2 text-muted">Severity: ${vuln.severity}</h6>
                                <p class="card-text"><strong>URL:</strong> ${vuln.url}</p>
                                <p class="card-text"><strong>Evidence:</strong> ${vuln.evidence}</p>
                                <p class="card-text"><strong>Description:</strong> ${vuln.description}</p>
                            </div>
                        </div>
                    `).join('');
                }
                
                // Update statistics
                function updateStats() {
                    const stats = document.getElementById('stats');
                    const severityCounts = {};
                    
                    scanResults.vulnerabilities.forEach(vuln => {
                        severityCounts[vuln.severity] = (severityCounts[vuln.severity] || 0) + 1;
                    });
                    
                    stats.innerHTML = `
                        <p><strong>Total Vulnerabilities:</strong> ${scanResults.vulnerabilities.length}</p>
                        <canvas id="severityChart"></canvas>
                    `;
                    
                    // Create severity chart
                    new Chart(document.getElementById('severityChart'), {
                        type: 'pie',
                        data: {
                            labels: Object.keys(severityCounts),
                            datasets: [{
                                data: Object.values(severityCounts),
                                backgroundColor: [
                                    '#dc3545', // Critical
                                    '#fd7e14', // High
                                    '#ffc107', // Medium
                                    '#28a745', // Low
                                    '#17a2b8'  // Info
                                ]
                            }]
                        }
                    });
                }
                
                // Update type filter options
                function updateTypeFilter() {
                    const typeFilter = document.getElementById('typeFilter');
                    const types = new Set(scanResults.vulnerabilities.map(v => v.type));
                    
                    typeFilter.innerHTML = '<option value="">All</option>' +
                        Array.from(types).map(type => 
                            `<option value="${type}">${type}</option>`
                        ).join('');
                }
                
                // Handle filter form submission
                document.getElementById('filterForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const severity = document.getElementById('severityFilter').value;
                    const type = document.getElementById('typeFilter').value;
                    const url = document.getElementById('urlFilter').value;
                    
                    try {
                        const response = await fetch(`/api/filter?severity=${severity}&type=${type}&url=${url}`);
                        const filtered = await response.json();
                        scanResults.filtered_vulnerabilities = filtered.vulnerabilities;
                        updateVulnList(true);
                    } catch (error) {
                        console.error('Error applying filters:', error);
                    }
                });
                
                // Initial load
                fetchResults();
            </script>
        </body>
        </html>
        """)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True) 