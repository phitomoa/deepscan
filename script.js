document.addEventListener('DOMContentLoaded', () => {
    const startBtn = document.getElementById('start-scan-btn');
    const keywordInput = document.getElementById('keyword');
    const exclusionsInput = document.getElementById('exclusions');
    
    const scanningProcess = document.getElementById('scanning-process');
    const terminalOutput = document.getElementById('terminal-output');
    const progressContainer = document.getElementById('progress-container');
    const progressBarFill = document.getElementById('progress-fill');
    const scanPercentage = document.getElementById('scan-percentage');
    const scanStatusText = document.getElementById('scan-status-text');
    
    const resultsPanel = document.getElementById('results-panel');
    const resultsBody = document.getElementById('results-body');
    const threatCount = document.getElementById('threat-count');
    const metaKeyword = document.getElementById('meta-keyword');
    const metaExclusions = document.getElementById('meta-exclusions');

    // Mocks
    const prefixes = ['login-', 'secure-', 'auth-', 'update-', 'support-', 'verify-', 'app-', 'my-', 'account-', 'e-', 'portal-'];
    const suffixes = ['-secure', '-login', '-update', '-online', '-verify', '-official', '-support', '-service', '-id'];
    const tlds = ['.xyz', '.top', '.online', '.site', '.tk', '.ml', '.cf', '.gq', '.info', '.biz', '.cc', '.ws', '.click'];
    const riskLevels = ['Critical', 'High', 'High', 'Moderate', 'Moderate', 'Moderate'];
    
    const statusMessages = [
        "Menghubungkan ke jaringan node global...",
        "Menginisialisasi algoritma pendeteksi heuristik...",
        "Memindai registri domain tingkat atas (TLD)...",
        "Menganalisis sertifikat SSL yang mencurigakan...",
        "Memeriksa database WHOIS yang disembunyikan...",
        "Mengekstrak data dari zona DNS...",
        "Cross-referencing dengan blacklist internasional...",
        "Mem-bypass perlindungan anti-bot pada target...",
        "Menghimpun indikator kompromi (IoC)...",
        "Menyelesaikan kompilasi data ancaman..."
    ];

    function getRandomItem(arr) {
        return arr[Math.floor(Math.random() * arr.length)];
    }

    function generateRandomIP() {
        return `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
    }

    function addTerminalLine(text, type = '') {
        const p = document.createElement('p');
        p.className = type;
        const time = new Date().toISOString().split('T')[1].substring(0, 8);
        p.textContent = `[${time}] ${text}`;
        terminalOutput.appendChild(p);
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }

    function isExcluded(url, exclusions) {
        if (!exclusions || exclusions.length === 0) return false;
        const lowerUrl = url.toLowerCase();
        return exclusions.some(ex => {
            const term = ex.trim().toLowerCase();
            return term.length > 0 && lowerUrl.includes(term);
        });
    }

    function generateFakeResults(keyword, exclusionsList) {
        const results = [];
        const numResults = Math.floor(Math.random() * 15) + 8; // 8 to 22 results
        
        const baseKey = keyword.toLowerCase().replace(/\s+/g, '');

        let attempts = 0;
        while(results.length < numResults && attempts < 100) {
            attempts++;
            
            let formatType = Math.floor(Math.random() * 4);
            let domain = "";
            let randomStr = Math.random().toString(36).substring(2, 6);

            switch(formatType) {
                case 0: domain = `${getRandomItem(prefixes)}${baseKey}${getRandomItem(tlds)}`; break;
                case 1: domain = `${baseKey}${getRandomItem(suffixes)}${getRandomItem(tlds)}`; break;
                case 2: domain = `${baseKey}-${randomStr}${getRandomItem(tlds)}`; break;
                case 3: domain = `${getRandomItem(prefixes)}${baseKey}${getRandomItem(suffixes)}${getRandomItem(tlds)}`; break;
            }

            if (!isExcluded(domain, exclusionsList) && !results.find(r => r.url === domain)) {
                results.push({
                    url: domain,
                    ip: generateRandomIP(),
                    status: Math.random() > 0.3 ? 'Active' : 'Offline/Sinkholed',
                    risk: getRandomItem(riskLevels)
                });
            }
        }

        // Sort by risk (Critical first)
        const riskWeights = { 'Critical': 3, 'High': 2, 'Moderate': 1 };
        results.sort((a, b) => riskWeights[b.risk] - riskWeights[a.risk]);

        return results;
    }

    async function runScanSimulation(keyword, exclusionsText) {
        const exclusionsList = exclusionsText.split(',').filter(x => x.trim().length > 0);
        
        // Setup UI
        scanningProcess.classList.remove('hidden');
        progressContainer.classList.remove('hidden');
        resultsPanel.classList.add('hidden');
        startBtn.disabled = true;
        terminalOutput.innerHTML = '';
        progressBarFill.style.width = '0%';
        
        addTerminalLine(`> ENGINE START: Target [${keyword}]`, 'sys-msg');
        if (exclusionsList.length > 0) {
            addTerminalLine(`> EXCLUSIONS APPLIED: ${exclusionsList.join(' | ')}`, 'warn-msg');
        }

        let progress = 0;
        const totalDuration = 6000; // 6 seconds
        const intervalTime = 150;
        const steps = totalDuration / intervalTime;
        let msgIndex = 0;

        return new Promise((resolve) => {
            const interval = setInterval(() => {
                progress += (100 / steps) + (Math.random() * 2 - 1); // some randomness
                if (progress >= 100) progress = 100;

                progressBarFill.style.width = `${progress}%`;
                scanPercentage.textContent = `${Math.floor(progress)}%`;

                // Add random terminal logs
                if (Math.random() > 0.6) {
                    const ips = generateRandomIP();
                    addTerminalLine(`Scanning sector ${ips}... [OK]`);
                }

                // Update status messages
                if (progress > (msgIndex * 10) && msgIndex < statusMessages.length) {
                    scanStatusText.textContent = statusMessages[msgIndex];
                    addTerminalLine(`> ${statusMessages[msgIndex]}`, 'sys-msg');
                    msgIndex++;
                }

                if (progress >= 100) {
                    clearInterval(interval);
                    addTerminalLine(`> SYSTEM: Scan Complete. Parsing results...`, 'sys-msg');
                    scanStatusText.textContent = "Selesai.";
                    setTimeout(() => resolve(generateFakeResults(keyword, exclusionsList)), 500);
                }
            }, intervalTime);
        });
    }

    function renderResults(results, keyword, exclusionsText) {
        resultsBody.innerHTML = '';
        metaKeyword.textContent = keyword;
        metaExclusions.textContent = exclusionsText || 'Tidak ada';
        threatCount.textContent = `${results.length} Ancaman Ditemukan`;

        results.forEach(res => {
            const tr = document.createElement('tr');
            
            let riskClass = '';
            if (res.risk === 'Critical') riskClass = 'risk-critical';
            else if (res.risk === 'High') riskClass = 'risk-high';
            else if (res.risk === 'Moderate') riskClass = 'risk-moderate';

            tr.innerHTML = `
                <td><strong>${res.url}</strong></td>
                <td>${res.ip}</td>
                <td>${res.status}</td>
                <td class="${riskClass}">${res.risk}</td>
            `;
            resultsBody.appendChild(tr);
        });

        scanningProcess.classList.add('hidden');
        resultsPanel.classList.remove('hidden');
    }

    startBtn.addEventListener('click', async () => {
        const keyword = keywordInput.value.trim();
        const exclusions = exclusionsInput.value.trim();

        if (!keyword) {
            alert('Mohon masukkan kata kunci pencarian (Target)!');
            keywordInput.focus();
            return;
        }

        const results = await runScanSimulation(keyword, exclusions);
        renderResults(results, keyword, exclusions);
        startBtn.disabled = false;
        startBtn.innerHTML = '<span class="btn-text">SCAN ULANG</span><div class="btn-glow"></div>';
    });
});
