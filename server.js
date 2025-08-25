const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API endpoint to analyze a single page
app.post('/api/analyze-page', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        console.log(`Analyzing page: ${url}`);
        
        // Fetch the page with enhanced CSP detection
        const response = await fetchWithEnhancedDetection(url);

        // Check for CSP in headers
        const cspHeader = response.headers['content-security-policy'] || 
                         response.headers['content-security-policy-report-only'];

        if (cspHeader) {
            return res.json({
                url: url,
                csp: cspHeader,
                source: 'header',
                status: 'success'
            });
        }

        // If no CSP in headers, check HTML meta tags
        const html = response.data;
        const $ = cheerio.load(html);
        
        // Look for CSP meta tag
        const cspMeta = $('meta[http-equiv="Content-Security-Policy"]').attr('content') ||
                       $('meta[http-equiv="content-security-policy"]').attr('content');

        if (cspMeta) {
            return res.json({
                url: url,
                csp: cspMeta,
                source: 'meta tag',
                status: 'success'
            });
        }

        // No CSP found
        return res.json({
            url: url,
            csp: 'No CSP found',
            source: 'none',
            status: 'success'
        });

    } catch (error) {
        console.error(`Error analyzing ${req.body.url}:`, error.message);
        
        let errorMessage = 'Failed to fetch page';
        if (error.response) {
            errorMessage = `HTTP ${error.response.status}: ${error.response.statusText}`;
        } else if (error.code === 'ECONNABORTED') {
            errorMessage = 'Request timeout';
        } else if (error.code === 'ENOTFOUND') {
            errorMessage = 'Domain not found';
        } else if (error.code === 'ECONNREFUSED') {
            errorMessage = 'Connection refused';
        }

        res.json({
            url: req.body.url,
            error: errorMessage,
            csp: null,
            status: 'error'
        });
    }
});

// API endpoint to process sitemap
app.post('/api/process-sitemap', async (req, res) => {
    try {
        const { sitemapUrl } = req.body;
        
        if (!sitemapUrl) {
            return res.status(400).json({ error: 'Sitemap URL is required' });
        }

        console.log(`Processing sitemap: ${sitemapUrl}`);
        
        const response = await fetchWithEnhancedDetection(sitemapUrl);

        const xmlText = response.data;
        const urls = extractUrlsFromSitemap(xmlText);
        
        res.json({
            urls: urls,
            totalUrls: urls.length,
            status: 'success'
        });

    } catch (error) {
        console.error(`Error processing sitemap:`, error.message);
        
        let errorMessage = 'Failed to fetch sitemap';
        if (error.response) {
            errorMessage = `HTTP ${error.response.status}: ${error.response.statusText}`;
        }

        res.status(500).json({
            error: errorMessage,
            status: 'error'
        });
    }
});

// API endpoint to analyze multiple URLs
app.post('/api/analyze-urls', async (req, res) => {
    try {
        const { urls } = req.body;
        
        if (!urls || !Array.isArray(urls)) {
            return res.status(400).json({ error: 'URLs array is required' });
        }

        console.log(`Analyzing ${urls.length} URLs`);
        
        const results = [];
        
        for (let i = 0; i < urls.length; i++) {
            const url = urls[i];
            console.log(`Processing ${i + 1}/${urls.length}: ${url}`);
            
            try {
                const response = await fetchWithEnhancedDetection(url);

                // Check for CSP in headers
                const cspHeader = response.headers['content-security-policy'] || 
                                 response.headers['content-security-policy-report-only'];

                if (cspHeader) {
                    results.push({
                        url: url,
                        csp: cspHeader,
                        source: 'header',
                        status: 'success'
                    });
                    continue;
                }

                // If no CSP in headers, check HTML meta tags
                const html = response.data;
                const $ = cheerio.load(html);
                
                const cspMeta = $('meta[http-equiv="Content-Security-Policy"]').attr('content') ||
                               $('meta[http-equiv="content-security-policy"]').attr('content');

                if (cspMeta) {
                    results.push({
                        url: url,
                        csp: cspMeta,
                        source: 'meta tag',
                        status: 'success'
                    });
                } else {
                    results.push({
                        url: url,
                        csp: 'No CSP found',
                        source: 'none',
                        status: 'success'
                    });
                }

            } catch (error) {
                console.error(`Error analyzing ${url}:`, error.message);
                
                let errorMessage = 'Failed to fetch page';
                if (error.response) {
                    errorMessage = `HTTP ${error.response.status}: ${error.response.statusText}`;
                } else if (error.code === 'ECONNABORTED') {
                    errorMessage = 'Request timeout';
                } else if (error.code === 'ENOTFOUND') {
                    errorMessage = 'Domain not found';
                } else if (error.code === 'ECONNREFUSED') {
                    errorMessage = 'Connection refused';
                }

                results.push({
                    url: url,
                    error: errorMessage,
                    csp: null,
                    status: 'error'
                });
            }
        }

        res.json({
            results: results,
            totalUrls: urls.length,
            status: 'success'
        });

    } catch (error) {
        console.error('Error in batch analysis:', error.message);
        res.status(500).json({
            error: 'Batch analysis failed',
            status: 'error'
        });
    }
});

// Helper function to extract URLs from sitemap XML
function extractUrlsFromSitemap(xmlText) {
    const urlRegex = /<loc>(.*?)<\/loc>/g;
    const urls = [];
    let match;
    
    while ((match = urlRegex.exec(xmlText)) !== null) {
        const url = match[1].trim();
        if (url && isValidUrl(url)) {
            urls.push(url);
        }
    }
    
    return urls;
}

// Helper function to validate URLs
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

        // Enhanced CSP detection with multiple strategies
        async function fetchWithEnhancedDetection(url) {
            const strategies = [
                // Strategy 1: Standard fetch with timeout
                async () => {
                    return await axios.get(url, {
                        timeout: 30000,
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'DNT': '1',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '1'
                        }
                    });
                },
                
                // Strategy 2: Fetch with longer timeout for slow-loading pages
                async () => {
                    return await axios.get(url, {
                        timeout: 45000,
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'DNT': '1',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '1'
                        }
                    });
                },
                
                // Strategy 3: Fetch with different User-Agent
                async () => {
                    return await axios.get(url, {
                        timeout: 30000,
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'DNT': '1',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '1'
                        }
                    });
                }
            ];

            for (let i = 0; i < strategies.length; i++) {
                try {
                    console.log(`Trying strategy ${i + 1} for ${url}`);
                    const response = await strategies[i]();
                    console.log(`Strategy ${i + 1} succeeded for ${url}`);
                    return response;
                } catch (error) {
                    console.warn(`Strategy ${i + 1} failed for ${url}:`, error.message);
                    if (i === strategies.length - 1) {
                        throw error; // Re-throw if all strategies failed
                    }
                    // Wait a bit before trying next strategy
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            }
        }

        // Start server
        app.listen(PORT, () => {
            console.log(`🚀 CSP Auditor Backend running on http://localhost:${PORT}`);
            console.log(`📊 Ready to analyze CSP directives without CORS restrictions!`);
        });
