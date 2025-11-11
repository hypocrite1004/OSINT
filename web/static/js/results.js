// Results page JavaScript

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadResults();
});

// Load scan results
async function loadResults() {
    try {
        const response = await fetch(`/api/scan/${scanId}/results`);

        if (!response.ok) {
            showError('결과를 불러올 수 없습니다');
            return;
        }

        const data = await response.json();
        displayResults(data);
    } catch (error) {
        console.error('Error loading results:', error);
        showError('결과를 불러오는 중 오류가 발생했습니다');
    }
}

// Display results
function displayResults(data) {
    // Hide loading, show content
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('resultsContent').style.display = 'block';

    // Set header info
    document.getElementById('targetName').textContent = data.target;
    document.getElementById('resultScanId').textContent = data.scan_id;

    // Set download buttons
    document.getElementById('downloadJsonBtnResult').onclick = () => {
        window.open(`/api/scan/${scanId}/download/json`, '_blank');
    };
    document.getElementById('downloadHtmlBtnResult').onclick = () => {
        window.open(`/api/scan/${scanId}/download/html`, '_blank');
    };

    // Display each section
    if (data.results.dns) {
        displayDNSResults(data.results.dns);
    }

    if (data.results.whois) {
        displayWHOISResults(data.results.whois);
    }

    if (data.results.subdomains) {
        displaySubdomainResults(data.results.subdomains);
    }

    if (data.results.ports) {
        displayPortResults(data.results.ports);
    }

    if (data.results.web) {
        displayWebResults(data.results.web);
    }

    if (data.results.api) {
        displayAPIResults(data.results.api);
    }

    // Display raw JSON
    displayRawJSON(data.results);
}

// Display DNS results
function displayDNSResults(dns) {
    const section = document.getElementById('dnsSection');
    const content = document.getElementById('dnsContent');

    if (dns.error) {
        content.innerHTML = `<p class="error">오류: ${dns.error}</p>`;
        section.style.display = 'block';
        return;
    }

    let html = '';

    // DNS Records
    if (dns.dns_records) {
        html += '<h3>DNS 레코드</h3>';
        for (const [type, records] of Object.entries(dns.dns_records)) {
            if (records && records.length > 0) {
                html += `<div class="list-item">
                    <strong>${type} 레코드:</strong><br>
                    ${records.map(r => `<code>${r}</code>`).join('<br>')}
                </div>`;
            }
        }
    }

    // Nameservers
    if (dns.nameservers && dns.nameservers.length > 0) {
        html += '<h3>네임서버</h3>';
        dns.nameservers.forEach(ns => {
            html += `<div class="list-item">${ns}</div>`;
        });
    }

    // MX Records
    if (dns.mx_records && dns.mx_records.length > 0) {
        html += '<h3>메일 서버 (MX)</h3>';
        html += '<table class="result-table"><thead><tr><th>우선순위</th><th>서버</th></tr></thead><tbody>';
        dns.mx_records.forEach(mx => {
            html += `<tr><td>${mx.preference}</td><td>${mx.exchange}</td></tr>`;
        });
        html += '</tbody></table>';
    }

    content.innerHTML = html;
    section.style.display = 'block';
}

// Display WHOIS results
function displayWHOISResults(whois) {
    const section = document.getElementById('whoisSection');
    const content = document.getElementById('whoisContent');

    if (whois.error) {
        content.innerHTML = `<p class="error">오류: ${whois.error}</p>`;
        section.style.display = 'block';
        return;
    }

    const whoisData = whois.whois_data || {};

    let html = '<table class="result-table"><thead><tr><th>항목</th><th>값</th></tr></thead><tbody>';

    for (const [key, value] of Object.entries(whoisData)) {
        if (value && key !== 'error') {
            const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            const displayValue = typeof value === 'object' ? JSON.stringify(value) : value;
            html += `<tr><td>${displayKey}</td><td>${displayValue}</td></tr>`;
        }
    }

    html += '</tbody></table>';

    // Analysis
    if (whois.analysis) {
        html += '<h3>분석</h3>';
        const analysis = whois.analysis;

        if (analysis.age_days !== null) {
            html += `<div class="list-item">도메인 나이: ${analysis.age_days}일</div>`;
        }
        if (analysis.expires_in_days !== null) {
            html += `<div class="list-item">만료까지: ${analysis.expires_in_days}일</div>`;
        }
        if (analysis.privacy_protected) {
            html += `<div class="list-item">프라이버시 보호: 활성화</div>`;
        }
    }

    content.innerHTML = html;
    section.style.display = 'block';
}

// Display subdomain results
function displaySubdomainResults(subdomains) {
    const section = document.getElementById('subdomainsSection');
    const content = document.getElementById('subdomainsContent');

    if (subdomains.error) {
        content.innerHTML = `<p class="error">오류: ${subdomains.error}</p>`;
        section.style.display = 'block';
        return;
    }

    const subs = subdomains.subdomains || [];

    let html = `<p>총 <strong>${subs.length}개</strong>의 서브도메인 발견</p>`;

    if (subs.length > 0) {
        html += '<table class="result-table"><thead><tr><th>서브도메인</th><th>IP 주소</th></tr></thead><tbody>';
        subs.forEach(sub => {
            html += `<tr><td><code>${sub.subdomain}</code></td><td>${sub.ips.join(', ')}</td></tr>`;
        });
        html += '</tbody></table>';
    }

    content.innerHTML = html;
    section.style.display = 'block';
}

// Display port scan results
function displayPortResults(ports) {
    const section = document.getElementById('portsSection');
    const content = document.getElementById('portsContent');

    if (ports.error) {
        content.innerHTML = `<p class="error">오류: ${ports.error}</p>`;
        section.style.display = 'block';
        return;
    }

    const openPorts = ports.open_ports || [];

    let html = `<p>총 <strong>${openPorts.length}개</strong>의 오픈 포트 발견</p>`;

    if (openPorts.length > 0) {
        html += '<table class="result-table"><thead><tr><th>포트</th><th>서비스</th><th>배너</th></tr></thead><tbody>';
        openPorts.forEach(port => {
            html += `<tr>
                <td><span class="badge badge-success">${port.port}</span></td>
                <td>${port.service}</td>
                <td>${port.banner || 'N/A'}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    }

    content.innerHTML = html;
    section.style.display = 'block';
}

// Display web analysis results
function displayWebResults(web) {
    const section = document.getElementById('webSection');
    const content = document.getElementById('webContent');

    if (web.error) {
        content.innerHTML = `<p class="error">오류: ${web.error}</p>`;
        section.style.display = 'block';
        return;
    }

    let html = '';

    // Response info
    if (web.response) {
        html += '<h3>응답 정보</h3>';
        html += `<div class="list-item">상태 코드: ${web.response.status_code}</div>`;
        if (web.response.final_url) {
            html += `<div class="list-item">최종 URL: ${web.response.final_url}</div>`;
        }
    }

    // Technologies
    if (web.technologies) {
        html += '<h3>감지된 기술</h3>';
        for (const [category, techs] of Object.entries(web.technologies)) {
            if (techs && techs.length > 0) {
                html += `<div class="list-item">
                    <strong>${category}:</strong><br>
                    ${techs.map(t => `<span class="badge badge-info">${t}</span>`).join(' ')}
                </div>`;
            }
        }
    }

    // Metadata
    if (web.metadata && web.metadata.title) {
        html += '<h3>메타데이터</h3>';
        html += `<div class="list-item"><strong>제목:</strong> ${web.metadata.title}</div>`;
        if (web.metadata.description) {
            html += `<div class="list-item"><strong>설명:</strong> ${web.metadata.description}</div>`;
        }
    }

    // SSL Certificate
    if (web.ssl_certificate && !web.ssl_certificate.error) {
        html += '<h3>SSL/TLS 인증서</h3>';
        const cert = web.ssl_certificate;
        if (cert.subject) {
            html += `<div class="list-item"><strong>주체:</strong> ${JSON.stringify(cert.subject)}</div>`;
        }
        if (cert.issuer) {
            html += `<div class="list-item"><strong>발급자:</strong> ${JSON.stringify(cert.issuer)}</div>`;
        }
        if (cert.not_after) {
            html += `<div class="list-item"><strong>만료일:</strong> ${cert.not_after}</div>`;
        }
    }

    // Contacts
    if (web.contacts && web.contacts.emails && web.contacts.emails.length > 0) {
        html += '<h3>발견된 이메일</h3>';
        web.contacts.emails.forEach(email => {
            html += `<div class="list-item">${email}</div>`;
        });
    }

    content.innerHTML = html;
    section.style.display = 'block';
}

// Display API results
function displayAPIResults(api) {
    const section = document.getElementById('apiSection');
    const content = document.getElementById('apiContent');

    let html = '';

    // Shodan
    if (api.shodan && !api.shodan.error) {
        html += '<h3>Shodan</h3>';
        const shodan = api.shodan;
        if (shodan.ports && shodan.ports.length > 0) {
            html += `<div class="list-item"><strong>오픈 포트:</strong> ${shodan.ports.join(', ')}</div>`;
        }
        if (shodan.vulns && shodan.vulns.length > 0) {
            html += `<div class="list-item"><strong>취약점:</strong> ${shodan.vulns.join(', ')}</div>`;
        }
        if (shodan.org) {
            html += `<div class="list-item"><strong>조직:</strong> ${shodan.org}</div>`;
        }
    }

    // VirusTotal
    if (api.virustotal && !api.virustotal.error) {
        html += '<h3>VirusTotal</h3>';
        const vt = api.virustotal;
        if (vt.reputation !== undefined) {
            html += `<div class="list-item"><strong>평판 점수:</strong> ${vt.reputation}</div>`;
        }
        if (vt.last_analysis_stats) {
            html += `<div class="list-item"><strong>분석 통계:</strong> ${JSON.stringify(vt.last_analysis_stats)}</div>`;
        }
    }

    // IPInfo
    if (api.ipinfo && !api.ipinfo.error) {
        html += '<h3>IP 정보</h3>';
        const ipinfo = api.ipinfo;
        if (ipinfo.city) {
            html += `<div class="list-item"><strong>위치:</strong> ${ipinfo.city}, ${ipinfo.region}, ${ipinfo.country}</div>`;
        }
        if (ipinfo.org) {
            html += `<div class="list-item"><strong>조직:</strong> ${ipinfo.org}</div>`;
        }
    }

    if (html) {
        content.innerHTML = html;
        section.style.display = 'block';
    }
}

// Display raw JSON
function displayRawJSON(results) {
    const jsonElement = document.getElementById('rawJson');
    jsonElement.textContent = JSON.stringify(results, null, 2);

    // Toggle button
    document.getElementById('toggleJsonBtn').onclick = () => {
        if (jsonElement.style.display === 'none') {
            jsonElement.style.display = 'block';
        } else {
            jsonElement.style.display = 'none';
        }
    };
}

// Show error
function showError(message) {
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('errorState').style.display = 'block';
    document.getElementById('errorMessage').textContent = message;
}
