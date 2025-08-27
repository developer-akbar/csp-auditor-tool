class CSPAuditor {
    constructor() {
        this.urls = [];
        this.results = [];
        this.currentIndex = 0;
        this.totalUrls = 0;
        this.startTime = 0;
        		this.apiBase = '/api';
		this.isProcessing = false;
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        document.getElementById('process-btn').addEventListener('click', () => this.startProcessing());
        document.getElementById('compare-btn').addEventListener('click', () => this.compareCDNRules());
        document.getElementById('copy-rule-btn').addEventListener('click', () => this.copyToClipboard());
        document.getElementById('copy-consolidated-btn').addEventListener('click', () => this.copyConsolidatedRule());
        document.getElementById('download-consolidated-btn').addEventListener('click', () => this.downloadConsolidatedRule());
        document.getElementById('analyze-blocked-btn').addEventListener('click', () => this.analyzeManualBlockedResources());
        const runtimeBtn = document.getElementById('runtime-audit-btn');
        if (runtimeBtn) runtimeBtn.addEventListener('click', () => this.runRuntimeAudit());
        // Radio button event listeners (do not clear results here; UX improvement)
        document.getElementById('sitemap-radio').addEventListener('change', () => this.switchInputType());
        document.getElementById('manual-radio').addEventListener('change', () => this.switchInputType());
    }

    switchInputType() {
        const sitemapRadio = document.getElementById('sitemap-radio');
        const manualRadio = document.getElementById('manual-radio');
        const sitemapInput = document.getElementById('sitemap-url');
        const manualInput = document.getElementById('manual-urls');
        
        if (sitemapRadio.checked) {
            sitemapInput.style.display = 'block';
            manualInput.style.display = 'none';
            sitemapInput.classList.add('input-field');
            manualInput.classList.remove('input-field');
            // Leave existing results; just reset corresponding input
            manualInput.value = '';
        } else {
            sitemapInput.style.display = 'none';
            manualInput.style.display = 'block';
            sitemapInput.classList.remove('input-field');
            manualInput.classList.add('input-field');
            sitemapInput.value = '';
        }
    }

    clearResults() {
        this.results = [];
        this.urls = [];
        this.currentIndex = 0;
        this.totalUrls = 0;
        this.startTime = 0;
        
        // Reset progress UI
        const fill = document.getElementById('progress-fill');
        if (fill) fill.style.width = '0%';
        const statusText = document.getElementById('status-text');
        if (statusText) statusText.textContent = 'Initializing...';
        const progressDetails = document.getElementById('progress-details');
        if (progressDetails) progressDetails.textContent = 'Preparing...';
        const completion = document.getElementById('completion-time');
        if (completion) { completion.textContent = ''; completion.style.display = 'none'; }

        // Hide progress initially but keep last results visible until new action starts
        document.getElementById('progress-section').style.display = 'none';
        document.getElementById('error-message').style.display = 'none';
        
        // Clear runtime summary and comparison artifacts
        const comp = document.getElementById('comparison-results'); if (comp) comp.classList.add('hidden');
        this.clearRuntimeSummary();
    }

    clearRuntimeSummary() {
        const rds = document.getElementById('runtime-directive-stats'); if (rds) rds.innerHTML = '';
        const rur = document.getElementById('runtime-updated-rule'); if (rur) rur.textContent = '';
        const dlj = document.getElementById('download-runtime-json'); if (dlj) { dlj.classList.add('disabled'); dlj.disabled = true; dlj.removeAttribute('href'); }
        const dle = document.getElementById('download-runtime-errors'); if (dle) { dle.classList.add('disabled'); dle.disabled = true; dle.removeAttribute('href'); }
        const copyRun = document.getElementById('copy-runtime-rule-btn'); if (copyRun) { copyRun.textContent = '📋 Copy Updated Rule'; copyRun.classList.remove('copied'); }
    }

    async startProcessing() {
        if (this.isProcessing) return;
        const sitemapRadio = document.getElementById('sitemap-radio');
        const isSitemap = sitemapRadio && sitemapRadio.checked;
        const sitemapUrl = document.getElementById('sitemap-url').value.trim();
        const manualUrls = document.getElementById('manual-urls').value.trim();

        if ((isSitemap && !sitemapUrl) || (!isSitemap && !manualUrls)) {
            this.showError('Please provide either a sitemap URL or manual URLs.');
            return;
        }

        this.isProcessing = true;
        try {
            // Set context before clearing old results
            const ctx = document.getElementById('results-context');
            if (ctx) {
                if (isSitemap) ctx.textContent = `Results: Sitemap Mode • ${sitemapUrl}`;
                else {
                    const urlsPreview = this.parseManualUrls(manualUrls).slice(0, 3);
                    const moreCount = Math.max(0, this.parseManualUrls(manualUrls).length - urlsPreview.length);
                    ctx.textContent = `Results: Manual URLs Mode • ${urlsPreview.join(', ')}${moreCount ? ` and ${moreCount} more` : ''}`;
                }
            }
            const status = document.getElementById('results-status');
            if (status) status.textContent = 'Processing new request... existing results will update when done.';

            // Clear results only when user starts a new action
            this.clearResults();
            // Keep context/status visible
            if (ctx) ctx.style.display = 'inline';
            if (status) status.style.display = 'inline';

            this.showProgress();
            this.startTime = Date.now();

            if (isSitemap) {
                await this.processSitemap(sitemapUrl);
            } else {
                this.urls = this.parseManualUrls(manualUrls);
            }

            this.totalUrls = this.urls.length;
            if (this.totalUrls === 0) {
                this.showError('No valid URLs found to process.');
                return;
            }

            await this.processUrls();
            this.displayResults();
            this.hideProgress();
            if (status) status.textContent = 'Completed.';
        } catch (error) {
            this.showError(`Error: ${error.message}`);
            this.hideProgress();
            const status = document.getElementById('results-status');
            if (status) status.textContent = 'Failed.';
        } finally {
            this.isProcessing = false;
        }
    }

    async processSitemap(sitemapUrl) {
        try {
            const response = await fetch(`${this.apiBase}/process-sitemap`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ sitemapUrl })
            });

            if (!response.ok) {
                throw new Error(`Failed to process sitemap: ${response.status}`);
            }

            const data = await response.json();
            if (data.status === 'error') {
                throw new Error(data.error);
            }

            this.urls = data.urls;
            console.log(`Extracted ${this.urls.length} URLs from sitemap`);
        } catch (error) {
            throw new Error(`Sitemap processing failed: ${error.message}`);
        }
    }

    parseManualUrls(urlsText) {
        return urlsText
            .split(/[\,\n]+/)
            .map(url => url.trim())
            .filter(url => url && this.isValidUrl(url));
    }

    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    async processUrls() {
        try {
            this.currentIndex = 0;
            
            // Process URLs one by one for real-time progress updates
            for (let i = 0; i < this.urls.length; i++) {
                this.currentIndex = i + 1;
                this.updateProgress();
                
                try {
                    const response = await fetch(`${this.apiBase}/analyze-page`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ url: this.urls[i] })
                    });

                    if (!response.ok) {
                        throw new Error(`Failed to analyze ${this.urls[i]}: ${response.status}`);
                    }

                    const data = await response.json();
                    if (data.status === 'error') {
                        throw new Error(data.error);
                    }

                    this.results.push(data);
                    
                    // Small delay to show progress
                    await new Promise(resolve => setTimeout(resolve, 100));
                    
                } catch (error) {
                    console.warn(`Failed to analyze ${this.urls[i]}:`, error.message);
                    this.results.push({
                        url: this.urls[i],
                        csp: 'Error: ' + error.message,
                        status: 'error'
                    });
                }
            }
            
            console.log(`Successfully analyzed ${this.results.length} URLs`);
        } catch (error) {
            throw new Error(`URL processing failed: ${error.message}`);
        }
    }

    updateProgress() {
        const progress = (this.currentIndex / this.totalUrls) * 100;
        document.getElementById('progress-fill').style.width = `${progress}%`;
        
        const elapsed = Date.now() - this.startTime;
        const avgTimePerUrl = elapsed / this.currentIndex;
        const remainingUrls = this.totalUrls - this.currentIndex;
        const estimatedTime = Math.round((avgTimePerUrl * remainingUrls) / 1000);
        
        // Show estimated time first
        document.getElementById('status-text').textContent = `Estimated time remaining: ${estimatedTime} seconds`;
        
        // Show current URL being processed with count
        const currentUrl = this.urls[this.currentIndex - 1] || '';
        const shortUrl = currentUrl.length > 50 ? currentUrl.substring(0, 50) + '...' : currentUrl;
        document.getElementById('progress-details').textContent = 
            `Processing: ${shortUrl} (${this.currentIndex}/${this.totalUrls})`;
    }

    displayResults() {
        const directiveStats = this.analyzeDirectives();
        this.displayDirectiveStats(directiveStats);
        this.generateConsolidatedCSP();
        this.generateDownloadFiles();
        this.displayCSPAnalysis(); // Add CSP analysis display
        this.showResults();
        
        // Enable download buttons
        document.getElementById('csv-download').classList.remove('disabled');
        document.getElementById('json-download').classList.remove('disabled');
        document.getElementById('csv-download').disabled = false;
        document.getElementById('json-download').disabled = false;
    }

    analyzeDirectives() {
        const stats = {};
        const allDirectives = new Set();

        this.results.forEach(result => {
            if (result.csp && result.csp !== 'No CSP found') {
                const directives = this.parseCSPDirectives(result.csp);
                directives.forEach(directive => {
                    allDirectives.add(directive.name);
                    if (!stats[directive.name]) {
                        stats[directive.name] = {
                            count: 0,
                            values: new Set()
                        };
                    }
                    stats[directive.name].count++;
                    directive.values.forEach(value => stats[directive.name].values.add(value));
                });
            }
        });

        return { stats, allDirectives };
    }

    parseCSPDirectives(cspString) {
        const directives = [];
        const directiveRegex = /([^;]+)/g;
        let match;

        while ((match = directiveRegex.exec(cspString)) !== null) {
            const directive = match[1].trim();
            const spaceIndex = directive.indexOf(' ');
            
            if (spaceIndex > 0) {
                const name = directive.substring(0, spaceIndex).trim();
                const values = directive.substring(spaceIndex + 1).trim().split(/\s+/);
                
                directives.push({
                    name: name,
                    values: values
                });
            }
        }

        return directives;
    }

    displayDirectiveStats(analysis) {
        const container = document.getElementById('directive-stats');
        container.innerHTML = '';

        Object.entries(analysis.stats).forEach(([directive, data]) => {
            const item = document.createElement('div');
            item.className = 'directive-item';
            
            // Show all values with proper scrolling
            const allValues = Array.from(data.values);
            const valuesHtml = allValues.map(value => `<span class="directive-value">${value}</span>`).join('');
            
            item.innerHTML = `
                <div class="directive-name">${directive}</div>
                <div class="directive-count">${data.count} pages</div>
                <div class="directive-values">
                    <small>${valuesHtml}</small>
                </div>
            `;
            container.appendChild(item);
        });
    }

    displayCSPAnalysis() {
        // Clean recommendation container and remove any previous accordion toggle
        const recommendationsList = document.getElementById('recommendations-list');
        const prevToggle = recommendationsList && recommendationsList.parentElement ? recommendationsList.parentElement.querySelector('.accordion-toggle') : null;
        if (prevToggle) prevToggle.remove();
        // Display blocked resources
        const blockedList = document.getElementById('blocked-list');
        blockedList.innerHTML = '';
        
        let hasBlockedResources = false;
        this.results.forEach(result => {
            if (result.analysis && result.analysis.blockedResources) {
                result.analysis.blockedResources.forEach(resource => {
                    hasBlockedResources = true;
                    const li = document.createElement('li');
                    li.innerHTML = `
                        <div class="blocked-resource-item">
                            <span class="blocked-resource-type">${resource.type}</span>
                            <div class="blocked-resource-url">${resource.url}</div>
                            <div class="blocked-resource-recommendation">${resource.recommendation}</div>
                        </div>
                    `;
                    blockedList.appendChild(li);
                });
            }
        });
        
        if (!hasBlockedResources) {
            blockedList.innerHTML = '<li>No blocked resources detected</li>';
        }
        
        // Display missing directives analysis
        const missingDirectivesList = document.getElementById('missing-directives-analysis-list');
        missingDirectivesList.innerHTML = '';
        
        let hasMissingDirectives = false;
        this.results.forEach(result => {
            if (result.analysis && result.analysis.missingDirectives) {
                result.analysis.missingDirectives.forEach(missing => {
                    hasMissingDirectives = true;
                    const li = document.createElement('li');
                    const examples = missing.examples && missing.examples.length > 0 
                        ? `<div class="missing-directive-examples">Examples: ${missing.examples.join(', ')}</div>`
                        : '';
                    li.innerHTML = `
                        <div class="missing-directive-item">
                            <div class="missing-directive-name">${missing.directive}</div>
                            <div class="missing-directive-reason">${missing.reason}</div>
                            ${examples}
                        </div>
                    `;
                    missingDirectivesList.appendChild(li);
                });
            }
        });
        
        if (!hasMissingDirectives) {
            missingDirectivesList.innerHTML = '<li>No missing directives detected</li>';
        }
        
        // Recommendations with accordion if more than 3
        if (recommendationsList) recommendationsList.innerHTML = '';
        
        const recs = [];
        this.results.forEach(result => {
            if (result.analysis && result.analysis.recommendations) {
                result.analysis.recommendations.forEach(recommendation => {
                    recs.push(recommendation);
                });
            }
        });
        
        if (recs.length === 0) {
            if (recommendationsList) recommendationsList.innerHTML = '<li>No specific recommendations at this time</li>';
            return;
        }
        
        const maxVisible = 3;
        const renderItems = (items) => {
            if (recommendationsList) recommendationsList.innerHTML = '';
            items.forEach(recommendation => {
                const li = document.createElement('li');
                li.className = 'recommendation-item';
                li.textContent = recommendation;
                recommendationsList.appendChild(li);
            });
        };

        if (recs.length > maxVisible) {
            renderItems(recs.slice(0, maxVisible));
            const toggle = document.createElement('button');
            toggle.className = 'accordion-toggle';
            toggle.textContent = `Show ${recs.length - maxVisible} more`;
            let expanded = false;
            toggle.onclick = () => {
                expanded = !expanded;
                if (expanded) {
                    renderItems(recs);
                    toggle.textContent = 'Show less';
                } else {
                    renderItems(recs.slice(0, maxVisible));
                    toggle.textContent = `Show ${recs.length - maxVisible} more`;
                }
                recommendationsList.parentElement.appendChild(toggle);
            };
            recommendationsList.parentElement.appendChild(toggle);
        } else {
            renderItems(recs);
        }
    }

    async analyzeManualBlockedResources() {
        const blockedResourcesText = document.getElementById('manual-blocked-resources').value.trim();
        
        if (!blockedResourcesText) {
            this.showError('Please enter blocked resource URLs to analyze.');
            return;
        }
        
        try {
            // Parse the blocked resources
            const blockedUrls = blockedResourcesText
                .split(/[\,\n]+/)
                .map(url => url.trim())
                .filter(url => url && this.isValidUrl(url));
            
            if (blockedUrls.length === 0) {
                this.showError('No valid URLs found in the input.');
                return;
            }
            
            // Analyze each blocked resource
            const analysis = [];
            for (const url of blockedUrls) {
                try {
                    const urlObj = new URL(url);
                    const hostname = urlObj.hostname;
                    const pathname = urlObj.pathname;
                    
                    // Determine the type of resource based on URL
                    let resourceType = 'script';
                    if (pathname.includes('.css') || pathname.includes('/css/')) {
                        resourceType = 'style';
                    } else if (pathname.includes('.js') || pathname.includes('/js/')) {
                        resourceType = 'script';
                    } else if (pathname.includes('.png') || pathname.includes('.jpg') || pathname.includes('.gif') || pathname.includes('.svg')) {
                        resourceType = 'image';
                    } else if (pathname.includes('.woff') || pathname.includes('.ttf') || pathname.includes('.eot')) {
                        resourceType = 'font';
                    }
                    
                    // Create recommendation
                    const directive = `${resourceType}-src`;
                    const recommendation = `Add ${hostname} to ${directive} directive`;
                    
                    analysis.push({
                        type: resourceType,
                        url: url,
                        directive: directive,
                        recommendation: recommendation,
                        hostname: hostname
                    });
                } catch (error) {
                    console.warn(`Failed to analyze URL ${url}:`, error.message);
                }
            }
            
            // Display the analysis results
            this.displayManualBlockedResourcesAnalysis(analysis);
            
        } catch (error) {
            this.showError(`Error analyzing blocked resources: ${error.message}`);
        }
    }

    displayManualBlockedResourcesAnalysis(analysis) {
        // Update the blocked resources list with manual analysis
        const blockedList = document.getElementById('blocked-list');
        blockedList.innerHTML = '';
        
        if (analysis.length === 0) {
            blockedList.innerHTML = '<li>No blocked resources to analyze</li>';
            return;
        }
        
        analysis.forEach(resource => {
            const li = document.createElement('li');
            li.innerHTML = `
                <div class="blocked-resource-item">
                    <span class="blocked-resource-type">${resource.type}</span>
                    <div class="blocked-resource-url">${resource.url}</div>
                    <div class="blocked-resource-recommendation">${resource.recommendation}</div>
                </div>
            `;
            blockedList.appendChild(li);
        });
        
        // Generate recommendations for updating CSP
        this.generateRecommendationsFromBlockedResources(analysis);
    }

    generateRecommendationsFromBlockedResources(analysis) {
        const recommendationsList = document.getElementById('recommendations-list');
        recommendationsList.innerHTML = '';
        
        // Group by directive
        const directiveGroups = {};
        analysis.forEach(resource => {
            if (!directiveGroups[resource.directive]) {
                directiveGroups[resource.directive] = new Set();
            }
            directiveGroups[resource.directive].add(resource.hostname);
        });
        
        // Generate recommendations
        Object.entries(directiveGroups).forEach(([directive, hostnames]) => {
            const hostnamesList = Array.from(hostnames);
            const recommendation = `Update ${directive} to include: ${hostnamesList.map(h => `https://${h}`).join(' ')}`;
            
            const li = document.createElement('li');
            li.className = 'recommendation-item';
            li.textContent = recommendation;
            recommendationsList.appendChild(li);
        });
        
        // Add general recommendation
        if (Object.keys(directiveGroups).length > 0) {
            const generalLi = document.createElement('li');
            generalLi.className = 'recommendation-item';
            generalLi.textContent = 'These blocked resources indicate missing domains in your CSP configuration. Update your CDN CSP rules accordingly.';
            recommendationsList.appendChild(generalLi);
        }
    }

    generateConsolidatedCSP() {
        const consolidatedDirectives = new Map();
        
        this.results.forEach(result => {
            if (result.csp && result.csp !== 'No CSP found') {
                const directives = this.parseCSPDirectives(result.csp);
                directives.forEach(directive => {
                    if (!consolidatedDirectives.has(directive.name)) {
                        consolidatedDirectives.set(directive.name, new Set());
                    }
                    directive.values.forEach(value => consolidatedDirectives.get(directive.name).add(value));
                });
            }
        });
        
        // Build consolidated CSP rule
        let consolidatedRule = '';
        consolidatedDirectives.forEach((values, name) => {
            consolidatedRule += `${name} ${Array.from(values).join(' ')}; `;
        });
        
        // Display consolidated rule
        document.getElementById('consolidated-rule').textContent = consolidatedRule.trim();
        
        // Store for download
        this.consolidatedCSP = {
            rule: consolidatedRule.trim(),
            directives: Object.fromEntries(
                Array.from(consolidatedDirectives.entries()).map(([name, values]) => [
                    name, Array.from(values)
                ])
            )
        };
    }

    generateDownloadFiles() {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const domain = this.extractDomain(this.urls[0] || 'unknown');
        
        // Generate CSV
        const csvContent = this.generateCSV();
        const csvBlob = new Blob([csvContent], { type: 'text/csv' });
        const csvUrl = URL.createObjectURL(csvBlob);
        document.getElementById('csv-download').href = csvUrl;
        document.getElementById('csv-download').download = `csp-analysis-${domain}-${timestamp}.csv`;

        // Generate JSON
        const jsonContent = JSON.stringify({
            metadata: {
                timestamp: new Date().toISOString(),
                totalUrls: this.totalUrls,
                domain: domain
            },
            results: this.results,
            consolidatedCSP: this.consolidatedCSP
        }, null, 2);
        const jsonBlob = new Blob([jsonContent], { type: 'application/json' });
        const jsonUrl = URL.createObjectURL(jsonBlob);
        document.getElementById('json-download').href = jsonUrl;
        document.getElementById('json-download').download = `csp-analysis-${domain}-${timestamp}.json`;
    }

    generateCSV() {
        const headers = ['URL', 'CSP Source', 'Content Security Policy', 'Error', 'Status'];
        const rows = [headers.join(',')];
        
        this.results.forEach(result => {
            const row = [
                result.url,
                result.source || 'N/A',
                result.csp || 'N/A',
                result.error || 'N/A',
                result.status || 'N/A'
            ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(',');
            rows.push(row);
        });
        
        return rows.join('\n');
    }

    extractDomain(url) {
        try {
            return new URL(url).hostname;
        } catch {
            return 'unknown';
        }
    }

    compareCDNRules() {
        const existingRule = document.getElementById('existing-cdn-rule').value.trim();
        if (!existingRule) {
            this.showError('Please enter your existing CDN CSP rule first.');
            return;
        }

        const { missing, removed } = this.findMissingDirectives(existingRule);
        const updatedRule = this.generateUpdatedRule(existingRule, missing);
        
        this.displayComparisonResults(missing, removed, updatedRule);
    }

    findMissingDirectives(existingRule) {
        const existingDirectives = this.parseCSPDirectives(existingRule);
        const existingNames = new Set(existingDirectives.map(d => d.name));
        const missing = [];
        const removed = [];

        // Find missing directives
        this.results.forEach(result => {
            if (result.csp && result.csp !== 'No CSP found') {
                const pageDirectives = this.parseCSPDirectives(result.csp);
                pageDirectives.forEach(directive => {
                    if (!existingNames.has(directive.name)) {
                        missing.push(directive);
                    }
                });
            }
        });

        // Find removed directives (directives in existing rule but not in results)
        const resultDirectives = new Set();
        this.results.forEach(result => {
            if (result.csp && result.csp !== 'No CSP found') {
                const pageDirectives = this.parseCSPDirectives(result.csp);
                pageDirectives.forEach(directive => {
                    resultDirectives.add(directive.name);
                });
            }
        });

        existingDirectives.forEach(directive => {
            if (!resultDirectives.has(directive.name)) {
                removed.push(directive);
            }
        });

        return { missing, removed };
    }

    generateUpdatedRule(existingRule, missingDirectives) {
        const uniqueMissing = new Map();
        missingDirectives.forEach(directive => {
            if (!uniqueMissing.has(directive.name)) {
                uniqueMissing.set(directive.name, directive);
            }
        });

        let updatedRule = existingRule;
        uniqueMissing.forEach(directive => {
            const newDirective = `${directive.name} ${Array.from(directive.values).join(' ')};`;
            updatedRule += ' ' + newDirective;
        });

        return updatedRule;
    }

    displayComparisonResults(missingDirectives, removedDirectives, updatedRule) {
        const missingContainer = document.getElementById('missing-directives');
        const removedContainer = document.getElementById('removed-directives');
        const updatedContainer = document.getElementById('updated-rule');
        const missingList = document.getElementById('missing-list');
        const removedList = document.getElementById('removed-list');
        const ruleText = document.getElementById('rule-text');
        const comparisonResults = document.getElementById('comparison-results');

        // Clear previous results
        missingList.innerHTML = '';
        removedList.innerHTML = '';

        // Display missing directives
        if (missingDirectives.length > 0) {
            const uniqueMissing = new Map();
            missingDirectives.forEach(directive => {
                if (!uniqueMissing.has(directive.name)) {
                    uniqueMissing.set(directive.name, directive);
                }
            });

            uniqueMissing.forEach(directive => {
                const li = document.createElement('li');
                li.textContent = `${directive.name}: ${Array.from(directive.values).join(' ')}`;
                missingList.appendChild(li);
            });
            missingContainer.style.display = 'block';
        } else {
            missingContainer.style.display = 'none';
        }

        // Display removed directives
        if (removedDirectives.length > 0) {
            removedDirectives.forEach(directive => {
                const li = document.createElement('li');
                li.textContent = `${directive.name}: ${Array.from(directive.values).join(' ')}`;
                removedList.appendChild(li);
            });
            removedContainer.style.display = 'block';
        } else {
            removedContainer.style.display = 'none';
        }

        // Display updated rule
        ruleText.textContent = updatedRule;
        updatedContainer.style.display = 'block';

        // Show comparison results
        comparisonResults.classList.remove('hidden');
    }

    async copyToClipboard() {
        const ruleText = document.getElementById('rule-text').textContent;
        try {
            await navigator.clipboard.writeText(ruleText);
            const btn = document.getElementById('copy-rule-btn');
            btn.textContent = '✅ Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = '📋 Copy Updated Rule';
                btn.classList.remove('copied');
            }, 2000);
        } catch (error) {
            this.showError('Failed to copy to clipboard. Please copy manually.');
        }
    }

    async copyConsolidatedRule() {
        const ruleText = document.getElementById('consolidated-rule').textContent;
        try {
            await navigator.clipboard.writeText(ruleText);
            const btn = document.getElementById('copy-consolidated-btn');
            btn.textContent = '✅ Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = '📋 Copy Consolidated Rule';
                btn.classList.remove('copied');
            }, 2000);
        } catch (error) {
            this.showError('Failed to copy to clipboard. Please copy manually.');
        }
    }

    downloadConsolidatedRule() {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const domain = this.extractDomain(this.urls[0] || 'unknown');
        
        const jsonContent = JSON.stringify({
            metadata: {
                timestamp: new Date().toISOString(),
                totalUrls: this.totalUrls,
                domain: domain
            },
            consolidatedCSP: this.consolidatedCSP
        }, null, 2);
        
        const jsonBlob = new Blob([jsonContent], { type: 'application/json' });
        const jsonUrl = URL.createObjectURL(jsonBlob);
        
        const link = document.createElement('a');
        link.href = jsonUrl;
        link.download = `consolidated-csp-${domain}-${timestamp}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    async runRuntimeAudit() {
        try {
            // Build URLs same as main flow
            const sitemapUrl = document.getElementById('sitemap-url').value.trim();
            const manualUrls = document.getElementById('manual-urls').value.trim();

            let urls = [];
            const sitemapRadio = document.getElementById('sitemap-radio');
            const isSitemap = sitemapRadio && sitemapRadio.checked;
            if (isSitemap && sitemapUrl) {
                const sm = await fetch(`${this.apiBase}/fetch-sitemap`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sitemapUrl })
                });
                const data = await sm.json();
                if (data.success) urls = data.urls;
            } else if (!isSitemap && manualUrls) {
                urls = this.parseManualUrls(manualUrls);
            }
            if (!urls || urls.length === 0) {
                this.showError('No valid URLs to audit.');
                return;
            }

            // Reset runtime section and progress
            this.clearRuntimeSummary();
            this.showProgress();
            const resp = await fetch(`${this.apiBase}/extract-csp`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ urls })
            });
            const result = await resp.json();
            this.hideProgress();
            if (!result.success) {
                this.showError(result.message || 'Runtime audit failed');
                return;
            }

            // Log summary to browser console for auditor clarity
            console.log('===== Runtime CSP Audit =====');
            console.log('URLs processed:', result.urlsProcessed);
            Object.entries(result.finalResult || {}).forEach(([dir, domains]) => {
                if (domains && domains.length) {
                    console.log(dir + ':');
                    domains.forEach(d => console.log('  - ' + d));
                }
            });
            console.log('Errors captured:', (result.cspErrors || []).length);

            // Render directive domains nicely
            const container = document.getElementById('runtime-directive-stats');
            if (container) {
                container.innerHTML = '';
                Object.entries(result.finalResult || {}).forEach(([directive, domains]) => {
                    if (!domains || domains.length === 0) return;
                    const item = document.createElement('div');
                    item.className = 'directive-item';
                    const valuesHtml = domains.map(value => `<span class=\"directive-value\">${value}</span>`).join('');
                    item.innerHTML = `
                        <div class=\"directive-name\">${directive}</div>
                        <div class=\"directive-count\">${domains.length} domains</div>
                        <div class=\"directive-values\"><small>${valuesHtml}</small></div>
                    `;
                    container.appendChild(item);
                });
            }

            // Updated CSP rule and copy
            const runtimeRule = (result.updatedCSP || '').trim();
            const ruleTextEl = document.getElementById('runtime-updated-rule');
            if (ruleTextEl) ruleTextEl.textContent = runtimeRule;
            const copyBtn = document.getElementById('copy-runtime-rule-btn');
            if (copyBtn) copyBtn.onclick = async () => {
                try {
                    await navigator.clipboard.writeText(runtimeRule);
                    copyBtn.textContent = '✅ Copied!';
                    copyBtn.classList.add('copied');
                    setTimeout(() => { copyBtn.textContent = '📋 Copy Updated Rule'; copyBtn.classList.remove('copied'); }, 2000);
                } catch (e) { this.showError('Failed to copy to clipboard.'); }
            };

            // Downloads
            const jsonBlob = new Blob([JSON.stringify(result.finalResult || {}, null, 2)], { type: 'application/json' });
            const jsonUrl = URL.createObjectURL(jsonBlob);
            const dlJson = document.getElementById('download-runtime-json');
            if (dlJson) { dlJson.href = jsonUrl; dlJson.download = `runtime-csp-domains.json`; dlJson.classList.remove('disabled'); dlJson.disabled = false; }

            const errorsBlob = new Blob([JSON.stringify(result.cspErrors || [], null, 2)], { type: 'application/json' });
            const errorsUrl = URL.createObjectURL(errorsBlob);
            const dlErr = document.getElementById('download-runtime-errors');
            if (dlErr) { dlErr.href = errorsUrl; dlErr.download = `csp_errors.json`; dlErr.classList.remove('disabled'); dlErr.disabled = false; }
        } catch (e) {
            this.hideProgress();
            this.showError('Runtime audit failed: ' + e.message);
        }
    }

    showProgress() {
        document.getElementById('progress-section').style.display = 'block';
        const fill = document.getElementById('progress-fill');
        if (fill) fill.style.width = '0%';
        document.getElementById('status-text').textContent = 'Initializing...';
        document.getElementById('progress-details').textContent = 'Preparing...';
        const completion = document.getElementById('completion-time');
        if (completion) { completion.textContent = ''; completion.style.display = 'none'; }
        document.getElementById('process-btn').disabled = true;
        document.getElementById('process-btn').querySelector('.spinner').classList.remove('hidden');
        document.getElementById('error-message').style.display = 'none';
    }

    hideProgress() {
        // Show completion time before hiding progress
        const totalTime = Date.now() - this.startTime;
        const totalTimeSeconds = Math.round(totalTime / 1000);
        const totalTimeMinutes = Math.floor(totalTimeSeconds / 60);
        const remainingSeconds = totalTimeSeconds % 60;
        
        let timeDisplay = `Total processing time: ${totalTimeSeconds} seconds`;
        if (totalTimeMinutes > 0) {
            timeDisplay = `Total processing time: ${totalTimeMinutes}m ${remainingSeconds}s`;
        }
        
        document.getElementById('completion-time').textContent = timeDisplay;
        document.getElementById('completion-time').style.display = 'block';
        
        // Also update results header run time message for persistence
        const runMsg = document.getElementById('run-time-message');
        if (runMsg) runMsg.textContent = timeDisplay;
        
        // Hide progress after a short delay to show completion time
        setTimeout(() => {
            document.getElementById('progress-section').style.display = 'none';
            document.getElementById('process-btn').disabled = false;
            document.getElementById('process-btn').querySelector('.spinner').classList.add('hidden');
        }, 2000);
    }

    showResults() {
        document.getElementById('results-section').style.display = 'block';
    }

    showError(message) {
        const errorElement = document.getElementById('error-message');
        errorElement.textContent = message;
        errorElement.style.display = 'block';
        setTimeout(() => {
            errorElement.style.display = 'none';
        }, 8000);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new CSPAuditor();
});
