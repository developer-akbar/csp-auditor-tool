const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// API endpoint to analyze a single page
app.post('/api/analyze-page', async (req, res) => {
	try {
		const { url } = req.body;
		
		if (!url) {
			return res.status(400).json({ error: 'URL is required' });
		}

		// Fetch the page with enhanced CSP detection
		const response = await fetchWithEnhancedDetection(url);

		// Check for CSP in headers
		const cspHeader = response.headers['content-security-policy'] || 
						 response.headers['content-security-policy-report-only'];

		if (cspHeader) {
			// Analyze the CSP for potential issues and missing directives
			const cspAnalysis = analyzeCSPDirectives(cspHeader, response.data);
			
			return res.json({
				url: url,
				csp: cspHeader,
				source: 'header',
				status: 'success',
				analysis: cspAnalysis
			});
		}
		
		// If no CSP in headers, check HTML meta tags
		const html = response.data;
		const $ = cheerio.load(html);
		
		// Look for CSP meta tag
		const cspMeta = $('meta[http-equiv="Content-Security-Policy"]').attr('content') ||
					  $('meta[http-equiv="content-security-policy"]').attr('content');

		if (cspMeta) {
			// Analyze the CSP for potential issues and missing directives
			const cspAnalysis = analyzeCSPDirectives(cspMeta, html);
			
			return res.json({
				url: url,
				csp: cspMeta,
				source: 'meta tag',
				status: 'success',
				analysis: cspAnalysis
			});
		}
		
		// Enhanced CSP detection: Look for CSP in script tags and other sources
		const allScripts = $('script').map((i, el) => $(el).html()).get();
		
		// Look for CSP patterns in script content
		let foundCSP = null;
		const cspPatterns = [
			/Content-Security-Policy["\s]*:["\s]*([^"'\n]+)/gi,
			/CSP["\s]*:["\s]*([^"'\n]+)/gi,
			/security["\s]*:["\s]*([^"'\n]+)/gi
		];
		
		for (const script of allScripts) {
			if (script) {
				for (const pattern of cspPatterns) {
					const match = script.match(pattern);
					if (match && match[1]) {
						foundCSP = match[1].trim();
						break;
					}
				}
				if (foundCSP) break;
			}
		}
		
		if (foundCSP) {
			// Analyze the CSP for potential issues and missing directives
			const cspAnalysis = analyzeCSPDirectives(foundCSP, html);
			
			return res.json({
				url: url,
				csp: foundCSP,
				source: 'script content',
				status: 'success',
				analysis: cspAnalysis
			});
		}
		
		// Look for CSP in data attributes and other HTML attributes
		const cspDataAttr = $('[data-csp], [data-content-security-policy]').attr('data-csp') ||
						  $('[data-csp], [data-content-security-policy]').attr('data-content-security-policy');
		
		if (cspDataAttr) {
			// Analyze the CSP for potential issues and missing directives
			const cspAnalysis = analyzeCSPDirectives(cspDataAttr, html);
			
			return res.json({
				url: url,
				csp: cspDataAttr,
				source: 'data attribute',
				status: 'success',
				analysis: cspAnalysis
			});
		}
		
		// Look for CSP in any attribute that might contain it
		const allElements = $('*');
		let cspInAttribute = null;
		
		allElements.each((i, el) => {
			const $el = $(el);
			const attrs = $el[0].attribs;
			
			if (attrs) {
				for (const [attrName, attrValue] of Object.entries(attrs)) {
					if (attrValue && (
						attrValue.includes('script-src') || 
						attrValue.includes('style-src') || 
						attrValue.includes('img-src') ||
						attrValue.includes('font-src') ||
						attrValue.includes('connect-src')
					)) {
						cspInAttribute = attrValue;
						return false; // break the loop
					}
				}
			}
		});
		
		if (cspInAttribute) {
			// Analyze the CSP for potential issues and missing directives
			const cspAnalysis = analyzeCSPDirectives(cspInAttribute, html);
			
			return res.json({
				url: url,
				csp: cspInAttribute,
				source: 'HTML attribute',
				status: 'success',
				analysis: cspAnalysis
			});
		}

		// No CSP found
		return res.json({
			url: url,
			csp: 'No CSP found',
			source: 'none',
			status: 'success',
			analysis: {
				missingDirectives: [],
				recommendations: ['No CSP found - consider implementing basic CSP directives'],
				blockedResources: []
			}
		});

	} catch (error) {
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

// API endpoint to analyze CSP violations and provide recommendations
app.post('/api/analyze-csp-violations', async (req, res) => {
	try {
		const { url, blockedResources, currentCSP } = req.body;
		
		if (!url) {
			return res.status(400).json({ error: 'URL is required' });
		}

		// Fetch the page to analyze resources
		const response = await fetchWithEnhancedDetection(url);
		const html = response.data;
		const $ = cheerio.load(html);
		
		// Extract all external resources that might need CSP directives
		const externalResources = extractExternalResources($, html);
		
		// Analyze current CSP and identify missing directives
		const analysis = analyzeCSPViolations(currentCSP, externalResources, blockedResources);
		
		return res.json({
			url: url,
			currentCSP: currentCSP,
			externalResources: externalResources,
			analysis: analysis,
			status: 'success'
		});

	} catch (error) {
		res.status(500).json({
			error: 'Failed to analyze CSP violations',
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

		const response = await fetchWithEnhancedDetection(sitemapUrl);

		const xmlText = response.data;
		const urls = extractUrlsFromSitemap(xmlText);
		
		res.json({
			urls: urls,
			totalUrls: urls.length,
			status: 'success'
		});

	} catch (error) {
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

		const results = [];
		
		for (let i = 0; i < urls.length; i++) {
			const url = urls[i];
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

// Helper function to analyze CSP directives and identify potential issues
function analyzeCSPDirectives(cspString, html) {
	const analysis = {
		missingDirectives: [],
		recommendations: [],
		blockedResources: [],
		externalDomains: new Set()
	};
	
	// Parse CSP directives
	const directives = parseCSPDirectives(cspString);
	
	// Extract external resources from HTML
	const $ = cheerio.load(html);
	const externalResources = extractExternalResources($, html);
	
	// Check for missing directives based on external resources
	const requiredDirectives = ['script-src', 'style-src', 'img-src', 'font-src', 'connect-src'];
	
	requiredDirectives.forEach(directive => {
		if (!directives.find(d => d.name === directive)) {
			analysis.missingDirectives.push({
				directive: directive,
				reason: `Required directive for external resources`,
				examples: externalResources[directive] || []
			});
		}
	});
	
	// Check for blocked resources
	externalResources.scripts.forEach(script => {
		if (!isAllowedByCSP(script, directives, 'script-src')) {
			analysis.blockedResources.push({
				type: 'script',
				url: script,
				directive: 'script-src',
				recommendation: `Add ${new URL(script).hostname} to script-src directive`
			});
		}
	});
	
	externalResources.styles.forEach(style => {
		if (!isAllowedByCSP(style, directives, 'style-src')) {
			analysis.blockedResources.push({
				type: 'style',
				url: style,
				directive: 'style-src',
				recommendation: `Add ${new URL(style).hostname} to style-src directive`
			});
		}
	});
	
	// Generate recommendations
	if (analysis.missingDirectives.length > 0) {
		analysis.recommendations.push('Add missing CSP directives for external resources');
	}
	
	if (analysis.blockedResources.length > 0) {
		analysis.recommendations.push('Update CSP directives to allow blocked resources');
	}
	
	// Check for unsafe practices
	if (cspString.includes("'unsafe-inline'")) {
		analysis.recommendations.push('Consider removing unsafe-inline for better security');
	}
	
	if (cspString.includes("'unsafe-eval'")) {
		analysis.recommendations.push('Consider removing unsafe-eval for better security');
	}
	
	return analysis;
}

// Helper function to parse CSP directives
function parseCSPDirectives(cspString) {
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

// Helper function to extract external resources from HTML
function extractExternalResources($, html) {
	const resources = {
		scripts: [],
		styles: [],
		images: [],
		fonts: [],
		connections: []
	};
	
	// Extract script sources
	$('script[src]').each((i, el) => {
		const src = $(el).attr('src');
		if (src && src.startsWith('http')) {
			resources.scripts.push(src);
		}
	});
	
	// Extract style sources
	$('link[rel="stylesheet"]').each((i, el) => {
		const href = $(el).attr('href');
		if (href && href.startsWith('http')) {
			resources.styles.push(href);
		}
	});
	
	// Extract image sources
	$('img[src]').each((i, el) => {
		const src = $(el).attr('src');
		if (src && src.startsWith('http')) {
			resources.images.push(src);
		}
	});
	
	// Extract font sources
	$('link[rel="preload"][as="font"], link[rel="font"]').each((i, el) => {
		const href = $(el).attr('href');
		if (href && href.startsWith('http')) {
			resources.fonts.push(href);
		}
	});
	
	// Look for dynamic script loading patterns
	const scriptContent = $('script').map((i, el) => $(el).html()).get().join(' ');
	
	// Find URLs in script content that might be loaded dynamically
	const urlPattern = /https?:\/\/[^\s"']+/g;
	const urlsInScripts = scriptContent.match(urlPattern) || [];
	
	urlsInScripts.forEach(url => {
		if (url.includes('.js') || url.includes('/js/')) {
			resources.scripts.push(url);
		} else if (url.includes('.css') || url.includes('/css/')) {
			resources.styles.push(url);
		}
	});
	
	return resources;
}

// Helper function to check if a resource is allowed by CSP
function isAllowedByCSP(resourceUrl, directives, directiveName) {
	try {
		const resourceHost = new URL(resourceUrl).hostname;
		const directive = directives.find(d => d.name === directiveName);
		
		if (!directive) return false;
		
		return directive.values.some(value => {
			if (value === "'self'") return false; // 'self' only allows same origin
			if (value === "'unsafe-inline'") return false; // Doesn't apply to external scripts
			if (value === "'unsafe-eval'") return false; // Doesn't apply to external scripts
			if (value.startsWith('http')) {
				const allowedHost = new URL(value).hostname;
				return allowedHost === resourceHost || resourceHost.endsWith('.' + allowedHost);
			}
			return false;
		});
	} catch (error) {
		return false;
	}
}

// Helper function to analyze CSP violations and provide recommendations
function analyzeCSPViolations(currentCSP, externalResources, blockedResources) {
	const analysis = {
		missingDirectives: [],
		blockedResources: blockedResources || [],
		recommendations: [],
		updatedCSP: currentCSP
	};
	
	// Parse current CSP
	const directives = parseCSPDirectives(currentCSP);
	
	// Check for missing directives based on external resources
	const requiredDirectives = ['script-src', 'style-src', 'img-src', 'font-src', 'connect-src'];
	
	requiredDirectives.forEach(directiveName => {
		if (!directives.find(d => d.name === directiveName)) {
			analysis.missingDirectives.push({
				directive: directiveName,
				reason: `Required for external resources`,
				examples: externalResources[directiveName.replace('-src', 's')] || []
			});
		}
	});
	
	// Generate recommendations for blocked resources
	if (blockedResources && blockedResources.length > 0) {
		blockedResources.forEach(resource => {
			analysis.recommendations.push(resource.recommendation);
		});
	}
	
	// Generate updated CSP with missing directives
	if (analysis.missingDirectives.length > 0) {
		analysis.updatedCSP = generateUpdatedCSP(currentCSP, analysis.missingDirectives, externalResources);
	}
	
	return analysis;
}

// Helper function to generate updated CSP with missing directives
function generateUpdatedCSP(currentCSP, missingDirectives, externalResources) {
	let updatedCSP = currentCSP;
	
	missingDirectives.forEach(missing => {
		const directiveName = missing.directive;
		const examples = missing.examples;
		
		if (examples && examples.length > 0) {
			// Extract unique domains from examples
			const domains = [...new Set(examples.map(url => {
				try {
					return new URL(url).hostname;
				} catch {
					return url;
				}
			}))];
			
			// Add the missing directive
			const newDirective = `${directiveName} 'self' ${domains.map(d => `https://${d}`).join(' ')};`;
			updatedCSP += ' ' + newDirective;
		}
	});
	
	return updatedCSP;
}

// Enhanced CSP detection with multiple strategies and page load delay
async function fetchWithEnhancedDetection(url) {
	const IS_VERCEL = !!process.env.VERCEL;
	const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS) || (IS_VERCEL ? 8000 : 30000);
	const FETCH_TIMEOUT_MS_LONG = Number(process.env.FETCH_TIMEOUT_MS_LONG) || (IS_VERCEL ? 9000 : 45000);
	const DELAY_SHORT_MS = Number(process.env.FETCH_DELAY_MS) || (IS_VERCEL ? 200 : 4000);
	const DELAY_LONG_MS = Number(process.env.FETCH_DELAY_MS_LONG) || (IS_VERCEL ? 300 : 6000);

	const doDelay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

	// On Vercel Hobby, keep it tight to avoid 10s function timeout
	const strategies = IS_VERCEL ? [
		async () => {
			const response = await axios.get(url, {
				timeout: FETCH_TIMEOUT_MS,
				headers: {
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
					'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
				}
			});
			await doDelay(DELAY_SHORT_MS);
			return response;
		}
	] : [
		// Strategy 1: Standard fetch with timeout and page load delay
		async () => {
			const response = await axios.get(url, {
				timeout: FETCH_TIMEOUT_MS,
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
			await doDelay(DELAY_SHORT_MS);
			return response;
		},
		// Strategy 2: Fetch with longer timeout and extended page load delay
		async () => {
			const response = await axios.get(url, {
				timeout: FETCH_TIMEOUT_MS_LONG,
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
			await doDelay(DELAY_LONG_MS);
			return response;
		},
		// Strategy 3: Different User-Agent
		async () => {
			const response = await axios.get(url, {
				timeout: FETCH_TIMEOUT_MS,
				headers: {
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
					'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
				}
			});
			await doDelay(DELAY_SHORT_MS);
			return response;
		}
	];

	for (let i = 0; i < strategies.length; i++) {
		try {
			const response = await strategies[i]();
			return response;
		} catch (error) {
			if (i === strategies.length - 1) throw error;
			await doDelay(IS_VERCEL ? 50 : 1000);
		}
	}
}

module.exports = (req, res) => app(req, res);