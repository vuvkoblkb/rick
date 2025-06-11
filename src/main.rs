use anyhow::{Context, Result};
use futures::{future::BoxFuture, stream::{self, StreamExt}}; // Tambahkan StreamExt
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use nonzero_ext::*;
use regex::Regex;
use reqwest::{
    header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT},
    Client,
};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use url::Url;

// Update konstanta untuk performa lebih baik
const REQUESTS_PER_SECOND: u32 = 25; // Ditingkatkan dari 10
const MAX_DEPTH: u32 = 3;           // Dikurangi dari 5 untuk fokus
const TIMEOUT_SECONDS: u64 = 10;     // Dikurangi dari 15
const MAX_URLS_PER_DOMAIN: usize = 500; // Dikurangi dari 1000
const MAX_CONCURRENT_REQUESTS: usize = 25; // Tambahkan ini

// Struktur error dan risk level tetap sama
#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Max depth reached")]
    MaxDepthReached,
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum RiskLevel {
    Critical,    
    High,        
    Medium,      
    Low,         
    Info,        
}

impl Scanner {
    // Update fungsi create_scan_rules() dengan rules yang lebih spesifik
    fn create_scan_rules() -> Vec<ScanRule> {
        vec![
            // Authentication & Authorization Endpoints
            ScanRule {
                pattern: r"(?i)(/login|/auth|/signin|/signup|/register|/oauth|/sso)(/callback|/token|/refresh|/verify)?".to_string(),
                sensitivity: 10,
                category: "Auth-Critical".to_string(),
                description: "Authentication endpoint - Potential auth bypass or token leaks".to_string(),
                risk_level: RiskLevel::Critical,
            },

            // Sensitive API Endpoints
            ScanRule {
                pattern: r"(?i)(/api/v[0-9]+/(users?|auth|admin|config|settings|security|password|reset))".to_string(),
                sensitivity: 9,
                category: "API-Sensitive".to_string(),
                description: "Sensitive API endpoint - Potential data exposure or privilege escalation".to_string(),
                risk_level: RiskLevel::Critical,
            },

            // GraphQL Endpoints
            ScanRule {
                pattern: r"(?i)(/graphql|/graphiql|/altair|/playground)(/console|/debug)?".to_string(),
                sensitivity: 9,
                category: "GraphQL".to_string(),
                description: "GraphQL endpoint - Check for introspection and access control".to_string(),
                risk_level: RiskLevel::Critical,
            },

            // Administrative Interfaces
            ScanRule {
                pattern: r"(?i)(/admin|/administrator|/manage|/dashboard|/console|/panel)(/.*)?".to_string(),
                sensitivity: 10,
                category: "Admin".to_string(),
                description: "Administrative interface - High-privilege area".to_string(),
                risk_level: RiskLevel::Critical,
            },

            // File Operations
            ScanRule {
                pattern: r"(?i)(/upload|/download|/import|/export|/files?)(/.*)?".to_string(),
                sensitivity: 8,
                category: "FileOps".to_string(),
                description: "File operation endpoint - Check for unrestricted file operations".to_string(),
                risk_level: RiskLevel::High,
            },

            // Debug & Development
            ScanRule {
                pattern: r"(?i)(/debug|/dev|/test|/stage|/beta|/phpinfo\.php)".to_string(),
                sensitivity: 9,
                category: "Debug".to_string(),
                description: "Debug/test endpoint - Potential information disclosure".to_string(),
                risk_level: RiskLevel::High,
            },

            // Database & Backup Related
            ScanRule {
                pattern: r"(?i)(/backup|/dump|/db|/database|/sql|/phpmyadmin|/adminer)".to_string(),
                sensitivity: 10,
                category: "Database".to_string(),
                description: "Database related endpoint - Critical data exposure risk".to_string(),
                risk_level: RiskLevel::Critical,
            },

            // Config & Environment Files
            ScanRule {
                pattern: r"(?i)(\.env|\.git|\.config|\.cfg|\.ini|wp-config\.php|config\.php|settings\.php)$".to_string(),
                sensitivity: 10,
                category: "Config".to_string(),
                description: "Configuration file - Sensitive data exposure risk".to_string(),
                risk_level: RiskLevel::Critical,
            },

            // API Documentation
            ScanRule {
                pattern: r"(?i)(/swagger|/api-docs|/openapi|/swagger-ui|/redoc)".to_string(),
                sensitivity: 7,
                category: "API-Docs".to_string(),
                description: "API Documentation - Potential sensitive info exposure".to_string(),
                risk_level: RiskLevel::High,
            },

            // Service Workers & Background Tasks
            ScanRule {
                pattern: r"(?i)(/workers?|/tasks?|/jobs?|/queue|/cron|/webhook)".to_string(),
                sensitivity: 7,
                category: "Services".to_string(),
                description: "Background service endpoint - Check for unauthorized access".to_string(),
                risk_level: RiskLevel::High,
            },
        ]
    }

    // Tambahkan fungsi baru untuk analisis keamanan header
    async fn analyze_security_headers(&self, url: &str, headers: &HeaderMap, depth: u32) -> Result<()> {
        let critical_headers = [
            ("X-Frame-Options", "Missing X-Frame-Options - Clickjacking risk"),
            ("Content-Security-Policy", "Missing CSP - XSS risk"),
            ("Strict-Transport-Security", "Missing HSTS - SSL/TLS downgrade risk"),
            ("X-Content-Type-Options", "Missing X-Content-Type-Options - MIME sniffing risk"),
            ("X-XSS-Protection", "Missing X-XSS-Protection"),
        ];

        for (header, desc) in &critical_headers {
            if !headers.contains_key(*header) {
                let finding = Finding {
                    url: url.to_string(),
                    category: "Security-Headers".to_string(),
                    sensitivity: 8,
                    description: desc.to_string(),
                    depth,
                    risk_level: RiskLevel::High,
                };
                self.findings.lock().unwrap().push(finding);
            }
        }
        Ok(())
    }
}

impl Scanner {
    // Update fungsi scan_url untuk menangani concurrent scanning
    fn scan_url<'a>(&'a self, url: &'a str, depth: u32) -> BoxFuture<'a, Result<Vec<String>>> {
        Box::pin(async move {
            if depth >= self.config.max_depth {
                return Ok(Vec::new());
            }

            let domain = Url::parse(url)?
                .host_str()
                .context("Invalid URL")?
                .to_string();

            if !self.config.allowed_domains.contains(&domain) {
                return Ok(Vec::new());
            }

            {
                let mut urls_count = self.urls_per_domain.lock().unwrap();
                let count = urls_count.entry(domain).or_insert(0);
                if *count >= self.config.max_urls_per_domain {
                    return Ok(Vec::new());
                }
                *count += 1;
            }

            self.config.rate_limiter.until_ready().await;

            let mut new_urls = Vec::new();
            if let Ok(response) = self.client.get(url).send().await {
                // Analisis header keamanan
                self.analyze_security_headers(url, response.headers(), depth)?;
                
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        // Analisis konten
                        self.analyze_content(url, &body, depth)?;
                        self.analyze_sensitive_patterns(url, &body, depth)?;

                        // Ekstrak URL baru
                        if let Ok(extracted_urls) = self.extract_urls(url, &body) {
                            new_urls.extend(extracted_urls.into_iter().filter(|u| {
                                self.visited.lock().unwrap().insert(u.clone())
                            }));
                        }
                    }
                } else if response.status().is_client_error() {
                    // Catat endpoint yang mengembalikan 4xx sebagai potensial endpoint sensitif
                    let finding = Finding {
                        url: url.to_string(),
                        category: "Access-Control".to_string(),
                        sensitivity: 7,
                        description: format!("Restricted endpoint (Status: {})", response.status()),
                        depth,
                        risk_level: RiskLevel::High,
                    };
                    self.findings.lock().unwrap().push(finding);
                }
            }

            Ok(new_urls)
        })
    }

    // Update fungsi run untuk menggunakan concurrent scanning
    async fn run(&self, start_url: &str) -> Result<Vec<Finding>> {
        let mut pending_urls = vec![start_url.to_string()];
        let mut current_depth = 0;

        while !pending_urls.is_empty() && current_depth < self.config.max_depth {
            println!("Scanning depth {}: {} URLs pending", current_depth, pending_urls.len());
            
            let mut new_urls = Vec::new();
            
            // Process URLs concurrently in chunks
            for urls_chunk in pending_urls.chunks(MAX_CONCURRENT_REQUESTS) {
                let futures = urls_chunk.iter().map(|url| self.scan_url(url, current_depth));
                
                let results = stream::iter(futures)
                    .buffer_unordered(MAX_CONCURRENT_REQUESTS)
                    .collect::<Vec<_>>()
                    .await;

                for result in results {
                    if let Ok(urls) = result {
                        new_urls.extend(urls);
                    }
                }
            }

            pending_urls = new_urls;
            current_depth += 1;
        }

        // Generate report
        let findings = self.findings.lock().unwrap().to_vec();
        self.generate_report(&findings);

        Ok(findings)
    }

    // Tambahkan fungsi generate_report untuk output yang lebih terstruktur
    fn generate_report(&self, findings: &[Finding]) {
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();

        for finding in findings {
            match finding.risk_level {
                RiskLevel::Critical => critical.push(finding),
                RiskLevel::High => high.push(finding),
                RiskLevel::Medium => medium.push(finding),
                RiskLevel::Low => low.push(finding),
                _ => {}
            }
        }

        println!("\n=== SECURITY SCAN REPORT ===");
        println!("Total Findings: {}", findings.len());
        println!("Critical: {}", critical.len());
        println!("High: {}", high.len());
        println!("Medium: {}", medium.len());
        println!("Low: {}", low.len());
        println!("\n=== CRITICAL FINDINGS ===");
        
        for finding in critical {
            println!("\nEndpoint: {}", finding.url);
            println!("Category: {}", finding.category);
            println!("Risk: CRITICAL");
            println!("Description: {}", finding.description);
            println!("Depth: {}", finding.depth);
            println!("-----------------");
        }

        println!("\n=== HIGH RISK FINDINGS ===");
        for finding in high {
            println!("\nEndpoint: {}", finding.url);
            println!("Category: {}", finding.category);
            println!("Risk: HIGH");
            println!("Description: {}", finding.description);
            println!("Depth: {}", finding.depth);
            println!("-----------------");
        }
    }
}

impl Scanner {
    // Tambahkan fungsi baru untuk analisis pola sensitif yang lebih detail
    fn analyze_sensitive_patterns(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        let sensitive_patterns = [
            // Kredensial & Kunci API
            (r"(?i)(api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "API Key/Token Exposure"),
            (r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{3,})['\"]", "Password Exposure"),
            (r"(?i)authorization:\s*bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "JWT Token Exposure"),
            
            // Cloud Service Credentials
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            (r"(?i)(aws_secret|aws_key|aws_access)", "AWS Credential Reference"),
            (r"(?i)(azure|microsoft)\s*(key|token|secret)", "Azure Credential Reference"),
            
            // Database Connection Strings
            (r"(?i)(mongodb|postgres|mysql)(:\/\/|%3A%2F%2F)[^\s<>'\"]{10,}", "Database Connection String"),
            (r"(?i)jdbc:[a-z]+:\/\/[^\s<>'\"]+", "JDBC Connection String"),
            
            // Private Keys & Certificates
            (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", "Private Key Found"),
            (r"-----BEGIN CERTIFICATE-----", "Certificate Found"),
            
            // Internal Infrastructure
            (r"(?i)(internal|staging|test|dev)[-.]([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", "Internal Hostname"),
            (r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "IP Address"),
            
            // Development & Debug Info
            (r"(?i)((todo|fixme|hack|xxx|bug|debug):.*)", "Developer Comment"),
            (r"(?i)(error|exception|trace|debug).*log", "Log File Reference"),
        ];

        for (pattern, description) in &sensitive_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    let finding = Finding {
                        url: url.to_string(),
                        category: "Sensitive-Data".to_string(),
                        sensitivity: 10,
                        description: description.to_string(),
                        depth,
                        risk_level: RiskLevel::Critical,
                    };
                    self.findings.lock().unwrap().push(finding);
                }
            }
        }
        Ok(())
    }
}

// Update fungsi main dengan penanganan error yang lebih baik dan output yang lebih informatif
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <https://target_url> [depth]", args[0]);
        eprintln!("Example: {} https://example.com 3", args[0]);
        return Err(ScannerError::ConfigError("Missing target URL".to_string()).into());
    }

    let target_url = &args[1];
    
    // Validasi URL
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Err(ScannerError::ConfigError("URL must start with http:// or https://".to_string()).into());
    }

    println!("🔒 Security Scanner Starting...");
    println!("Target: {}", target_url);
    println!("Max Concurrent Requests: {}", MAX_CONCURRENT_REQUESTS);
    println!("Max Depth: {}", MAX_DEPTH);
    println!("Rate Limit: {} requests per second", REQUESTS_PER_SECOND);
    
    let start_time = std::time::Instant::now();
    
    println!("\n[*] Initializing scanner...");
    let scanner = Scanner::new(target_url).await?;
    
    println!("[*] Starting scan...");
    let findings = scanner.run(target_url).await?;
    
    let duration = start_time.elapsed();
    
    println!("\n=== SCAN COMPLETE ===");
    println!("Scan Duration: {:.2} seconds", duration.as_secs_f64());
    println!("Total Findings: {}", findings.len());
    
    // Menghitung statistik
    let critical_count = findings.iter().filter(|f| f.risk_level == RiskLevel::Critical).count();
    let high_count = findings.iter().filter(|f| f.risk_level == RiskLevel::High).count();
    
    if critical_count > 0 || high_count > 0 {
        println!("\n⚠️  ATTENTION ⚠️");
        println!("Found {} critical and {} high risk issues that require immediate attention!", 
                 critical_count, high_count);
        println!("\nRecommended Actions:");
        println!("1. Review all critical findings immediately");
        println!("2. Document and assess the risk of each finding");
        println!("3. Develop remediation plan for identified vulnerabilities");
        println!("4. Consider restricting access to sensitive endpoints");
    }

    Ok(())
}