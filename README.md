# 🔒 CSP Auditor - Content Security Policy Analysis Tool

A comprehensive web-based tool for analyzing and extracting Content Security Policy (CSP) directives from website pages. This tool helps developers and security professionals identify required CSP rules for CDN configuration and prevent "Refused to load the script" errors.

## ✨ Features

- **🌐 Sitemap Processing**: Automatically extract URLs from XML sitemaps
- **📝 Manual URL Input**: Process individual URLs or comma-separated lists
- **🔍 Enhanced CSP Detection**: Multiple strategies to ensure comprehensive CSP extraction
- **📊 Real-time Progress**: Live progress updates with URL-by-URL processing
- **📋 Consolidated CSP Rules**: Generate unified CSP rules from multiple pages
- **🔍 CDN Rule Comparison**: Compare existing CDN CSP rules with extracted directives
- **📥 Export Options**: Download results in CSV and JSON formats
- **⚡ Performance Optimized**: Intelligent retry mechanisms and timeout handling

## 🚀 Quick Start

### Prerequisites

- Node.js (version 16.0.0 or higher)
- npm (comes with Node.js)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/developer-akbar/csp-auditor-tool.git
   cd csp-auditor-tool
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the application**
   ```bash
   npm start
   ```

4. **Open your browser**
   Navigate to `http://localhost:3000`

### Alternative: Windows Batch File

If you're on Windows, you can use the provided batch file:
```bash
start.bat
```

## 🏗️ Architecture

### Frontend
- **HTML5**: Clean, modern interface with responsive design
- **CSS3**: Modular styles with smooth animations and progress indicators
- **Vanilla JavaScript**: No external frameworks, pure ES6+ code

### Backend
- **Node.js**: Server-side runtime environment
- **Express.js**: Web framework for API endpoints
- **Axios**: HTTP client with enhanced detection strategies
- **Cheerio**: HTML parsing for meta tag extraction

## 📡 API Endpoints

- `POST /api/analyze-page` - Analyze a single URL for CSP directives
- `POST /api/process-sitemap` - Extract URLs from XML sitemap
- `POST /api/analyze-urls` - Batch process multiple URLs

## 🔧 Enhanced CSP Detection

The tool implements multiple strategies to ensure comprehensive CSP extraction:

1. **Standard Fetch**: 30-second timeout with modern browser headers
2. **Extended Timeout**: 45-second timeout for slow-loading pages
3. **Alternative User-Agent**: Different browser identification
4. **Retry Mechanism**: Automatic fallback between strategies
5. **Error Handling**: Graceful degradation for failed requests

## 💡 Usage Examples

### Sitemap Analysis
1. Select "Sitemap URL" option
2. Enter your sitemap URL (e.g., `https://example.com/sitemap.xml`)
3. Click "Extract CSP Directives"
4. Monitor real-time progress
5. Download consolidated results

### Manual URL Processing
1. Select "Manual URLs" option
2. Enter URLs (one per line or comma-separated)
3. Click "Extract CSP Directives"
4. View individual page results

### CDN Rule Comparison
1. Extract CSP directives from your pages
2. Enter your existing CDN CSP rule
3. Click "Compare & Generate Updated Rule"
4. Copy the updated rule for your CDN configuration

## 📁 Project Structure

```
csp-auditor-tool/
├── public/
│   ├── index.html          # Main application interface
│   ├── styles.css          # Application styles
│   └── script.js           # Frontend logic
├── server.js               # Node.js backend server
├── package.json            # Project dependencies and scripts
├── start.bat              # Windows startup script
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## 🛠️ Development

### Running in Development Mode
```bash
npm run dev
```

This uses nodemon for automatic server restart on file changes.

### Building for Production
The application is ready for production deployment. Simply:
1. Install dependencies: `npm install --production`
2. Start the server: `npm start`
3. Set environment variables if needed (PORT, etc.)

## 🌐 Deployment

### Local Network
The application runs on `http://localhost:3000` by default. To make it accessible on your local network:

1. Find your local IP address
2. Access via `http://YOUR_IP:3000`

### Production Server
For production deployment:

1. **Environment Variables**
   ```bash
   export PORT=3000
   export NODE_ENV=production
   ```

2. **Process Manager** (recommended)
   ```bash
   npm install -g pm2
   pm2 start server.js --name "csp-auditor"
   pm2 startup
   pm2 save
   ```

3. **Reverse Proxy** (optional)
   Configure nginx or Apache to proxy requests to the Node.js application.

## 🔒 Security Considerations

- The tool makes HTTP requests to external websites
- No sensitive data is stored or transmitted
- All processing happens server-side to avoid CORS issues
- Consider rate limiting for production use

## 🐛 Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Find process using port 3000
   netstat -an | findstr :3000
   # Kill the process or change port in server.js
   ```

2. **CORS Errors**
   - The tool handles CORS server-side
   - Ensure you're accessing via the Node.js server, not directly opening HTML files

3. **Slow Processing**
   - Large sitemaps may take time
   - Progress is shown in real-time
   - Consider processing smaller batches for very large sites

### Performance Tips

- Process sitemaps in smaller chunks for very large sites
- Use manual URL input for specific page analysis
- The enhanced detection strategies may add processing time but ensure completeness

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with modern web technologies
- Designed for developer productivity and security analysis
- No external dependencies for the frontend

## 📞 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Fork and submit pull requests
- Contact the maintainer

---

**Happy CSP Auditing! 🔒✨**
