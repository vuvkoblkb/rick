use anyhow::{Context, Result};
use futures::future::BoxFuture;
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
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use url::Url;

const REQUESTS_PER_SECOND: u32 = 25;
const MAX_DEPTH: u32 = 3;
const TIMEOUT_SECONDS: u64 = 10;
const MAX_URLS_PER_DOMAIN: usize = 500;
const MAX_CONCURRENT_REQUESTS: usize = 25;

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

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "CRITICAL"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Finding {
    url: String,
    category: String,
    sensitivity: u8,
    description: String,
    depth: u32,
    risk_level: RiskLevel,
}

struct Scanner {
    client: Client,
    config: ScanConfig,
    visited: Arc<Mutex<HashSet<String>>>,
    findings: Arc<Mutex<Vec<Finding>>>,
    urls_per_domain: Arc<Mutex<HashMap<String, usize>>>,
}

#[derive(Debug, Clone)]
struct ScanConfig {
    max_depth: u32,
    max_urls_per_domain: usize,
    allowed_domains: HashSet<String>,
    scan_rules: Vec<ScanRule>,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScanRule {
    pattern: String,
    sensitivity: u8,
    category: String,
    description: String,
    risk_level: RiskLevel,
}

impl Scanner {
    fn analyze_advanced_vulnerabilities(&self, url: &str, content: &str, response_headers: &HeaderMap, depth: u32) -> Result<()> {
        let advanced_patterns = [
            // Prototype Pollution
            (r#"(?i)(Object\.prototype|__proto__|constructor\s*[=:])"#, "Prototype Pollution Vector", RiskLevel::Critical),
            
            // GraphQL Introspection & Injection
            (r#"(?i)(__schema|__type|__typename|\{[\s\n]*introspectionquery)"#, "GraphQL Introspection Exposure", RiskLevel::Critical),
            
            // Race Condition Vectors
            (r#"(?i)(/status|/check|/verify|/confirm|/process).*?(token|id|hash)="#, "Potential Race Condition", RiskLevel::Critical),
            
            // Type Confusion
            (r#"(?i)(typeof|instanceof|constructor\s*=|Object\.create)"#, "Type Confusion Vector", RiskLevel::High),
            
            // Memory Corruption
            (r#"(?i)(buffer|allocate|memory|heap|stack)\s*(overflow|corrupt|size|length)"#, "Memory Corruption Vector", RiskLevel::Critical),
            
            // Logic Bombs
            (r#"(?i)(setTimeout|setInterval|eval|new\s+Function)\s*\(.*?(payload|execute|run)"#, "Logic Bomb Pattern", RiskLevel::Critical),
            
            // WebSocket Vulnerabilities
            (r#"(?i)(ws:|wss:|new\s+WebSocket\(|socket\.)"#, "WebSocket Endpoint", RiskLevel::High),
            
            // Browser Exploitation
            (r#"(?i)(innerhtml|outerhtml|document\.write|eval\(|function\s*\(.*?\)\s*\{)"#, "Client-Side Execution", RiskLevel::Critical),
            
            // Advanced XSS Vectors
            (r#"(?i)(javascript:|data:text/html|vbscript:|<svg\s+onload|<img\s+onerror)"#, "Advanced XSS Vector", RiskLevel::Critical),
            
            // Server Side Request Forgery (SSRF)
            (r#"(?i)(curl_exec|file_get_contents|gopher://|redis://|ftp://)"#, "SSRF Vector", RiskLevel::Critical),
            
            // Advanced Injection Points
            (r#"(?i)(\$\{.*?\}|\{{2}.*?\}{2}|<\?.*?\?>)"#, "Template Injection Point", RiskLevel::Critical),
            
            // Deserialization
            (r#"(?i)(unserialize|deserialize|fromJson|parseObject|readObject)"#, "Deserialization Vector", RiskLevel::Critical),
            
            // Advanced File Operations
            (r#"(?i)(readfile|writefile|appendfile|copyfile|uploadfile)"#, "File Operation Vector", RiskLevel::High),

            // NoSQL Injection
            (r#"(?i)(\$where|\$regex|\$ne|\$gt|\$lt|\$exists)"#, "NoSQL Injection Vector", RiskLevel::Critical),
            
            // Process Control
            (r#"(?i)(exec|spawn|fork|system|shellexec|cmdexec)"#, "Process Execution Vector", RiskLevel::Critical),

            // Advanced Authentication Bypass
            (r#"(?i)(jwt\.sign|verify|check.*token|validate.*session)"#, "Auth Bypass Vector", RiskLevel::Critical),
        ];

        let response_analysis = [
            // Time-based Analysis
            |resp: &HeaderMap| {
                if let Some(timing) = resp.get("Server-Timing") {
                    if timing.to_str().unwrap_or("").contains("high") {
                        return Some(("Time-based Vulnerability", "High response time detected - potential for timing attacks"));
                    }
                }
                None
            },
            
            // Header Analysis
            |resp: &HeaderMap| {
                if !resp.contains_key("X-Frame-Options") && !resp.contains_key("Content-Security-Policy") {
                    return Some(("Security Headers Missing", "Critical security headers missing - potential for multiple attacks"));
                }
                None
            },
            
            // CORS Analysis
            |resp: &HeaderMap| {
                if let Some(cors) = resp.get("Access-Control-Allow-Origin") {
                    if cors.to_str().unwrap_or("") == "*" {
                        return Some(("CORS Misconfiguration", "Overly permissive CORS policy"));
                    }
                }
                None
            },
        ];

        // Analyze response headers for vulnerabilities
        for analyzer in &response_analysis {
            if let Some((category, description)) = analyzer(response_headers) {
                self.findings.lock().unwrap().push(Finding {
                    url: url.to_string(),
                    category: category.to_string(),
                    sensitivity: 10,
                    description: description.to_string(),
                    depth,
                    risk_level: RiskLevel::Critical,
                });
            }
        }

        // Parameter Analysis
        if let Ok(parsed_url) = Url::parse(url) {
            for (key, value) in parsed_url.query_pairs() {
                self.analyze_parameter(&key, &value, url, depth)?;
            }
        }

        Ok(())
    }

    fn analyze_parameter(&self, key: &str, value: &str, url: &str, depth: u32) -> Result<()> {
        let param_patterns = [
            (r#"\{\s*\$[^}]+\}"#, "Server-Side Template Injection"),
            (r#"['"]\s*\+\s*['"]\s*"#, "String Concatenation Attack"),
            (r#"\\/\\.\\.\\/"#, "Path Traversal Evasion"),
            (r#"\b(?:and|or|not|union|select|from|where)\b.*\b(?:and|or|not|union|select|from|where)\b"#, "SQL Injection Pattern"),
            (r#"\b(sh|bash|cmd|powershell)\b.*\b(exec|system|run)\b"#, "Command Injection Pattern"),
        ];

        for (pattern, vuln_type) in &param_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(value) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Parameter Exploitation".to_string(),
                        sensitivity: 10,
                        description: format!("Advanced {} detected in parameter {}", vuln_type, key),
                        depth,
                        risk_level: RiskLevel::Critical,
                    });
                }
            }
        }

        Ok(())
    }

    fn analyze_interactive_vectors(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        let interactive_patterns = [
            (r#"<form[^>]*>.*?</form>"#, "Form Detection", "Potential form submission point"),
            (r#"<input[^>]*type=["']?(file|hidden)["']?"#, "Special Input", "Special input type detected"),
            (r#"<script[^>]*>.*?</script>"#, "Script Block", "Client-side script detected"),
            (r#"onload|onerror|onmouseover|onclick|onsubmit"#, "Event Handler", "DOM event handler"),
            (r#"XMLHttpRequest|fetch\(|$.ajax"#, "AJAX Call", "Dynamic data transfer"),
            (r#"websocket|socket\.io"#, "WebSocket", "WebSocket communication"),
            (r#"localStorage|sessionStorage|indexedDB"#, "Client Storage", "Browser storage usage"),
            (r#"document\.cookie"#, "Cookie Access", "Cookie manipulation"),
        ];

        for (pattern, category, desc) in &interactive_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: category.to_string(),
                        sensitivity: 8,
                        description: desc.to_string(),
                        depth,
                        risk_level: RiskLevel::High,
                    });
                }
            }
        }
        Ok(())
    }

    fn analyze_request_response(&self, request_url: &str, response_headers: &HeaderMap, content: &str, depth: u32) -> Result<()> {
        if let Ok(parsed_url) = Url::parse(request_url) {
            let query_pairs = parsed_url.query_pairs();
            for (key, value) in query_pairs {
                let suspicious_chars = ["'", "\"", "<", ">", "(", ")", ";", "=", "|", "&"];
                for &char in suspicious_chars.iter() {
                    if value.contains(char) {
                        self.findings.lock().unwrap().push(Finding {
                            url: request_url.to_string(),
                            category: "Parameter Injection".to_string(),
                            sensitivity: 9,
                            description: format!("Suspicious character {} found in parameter {}", char, key),
                            depth,
                            risk_level: RiskLevel::High,
                        });
                    }
                }
            }
        }

        let sensitive_headers = [
            "X-Powered-By",
            "Server",
            "X-AspNet-Version",
            "X-Runtime",
        ];

        for &header in sensitive_headers.iter() {
            if let Some(value) = response_headers.get(header) {
                self.findings.lock().unwrap().push(Finding {
                    url: request_url.to_string(),
                    category: "Information Disclosure".to_string(),
                    sensitivity: 7,
                    description: format!("Sensitive header {} exposed: {}", header, value.to_str().unwrap_or("")),
                    depth,
                    risk_level: RiskLevel::Medium,
                });
            }
        }

        let content_patterns = [
            (r#"Exception|error|stack trace|debug"#, "Error Exposure"),
            (r#"SELECT.*FROM|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM"#, "SQL Query"),
            (r#"<\?php|eval\(|assert\(|system\("#, "Server-Side Code"),
        ];

        for (pattern, desc) in content_patterns.iter() {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: request_url.to_string(),
                        category: "Content Analysis".to_string(),
                        sensitivity: 9,
                        description: format!("{} detected in response", desc),
                        depth,
                        risk_level: RiskLevel::Critical,
                    });
                }
            }
        }

        Ok(())
    }

    fn analyze_sensitive_patterns(&self, url: &str, content: &str, depth: u32) -> Result<()> {
    let sensitive_patterns = [
        // Credentials & API Keys
        (r#"(?i)(api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']([^"']{8,})["']"#, "API Key/Token Exposure"),
        (r#"(?i)(password|passwd|pwd|pass)["']?\s*[:=]\s*["'][^"']{3,}["']"#, "Password Exposure"),
        (r#"(?i)(bearer\s+|jwt\s+|token\s+)[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#, "JWT Token Exposure"),
        
        // Database Connection Strings
        (r#"(?i)(mongodb|postgres|mysql|redis|elasticsearch|cassandra|couchdb)://([^@\s]+@)?[^\s<>"']{10,}"#, "Database Connection String"),
        (r#"(?i)jdbc:[a-z]+://[^\s<>"']+"#, "JDBC Connection String"),
        
        // Cloud Service Credentials
        (r#"AKIA[0-9A-Z]{16,}"#, "AWS Access Key ID"),
        (r#"(?i)(aws[_-]?(secret|key|token|id))"#, "AWS Credential Reference"),
        (r#"(?i)(azure|microsoft)[_-]?(key|token|secret|connection|pwd)"#, "Azure Credential Reference"),
        (r#"(?i)(google|gcp)[_-]?(key|token|secret|credential|pwd)"#, "Google Cloud Credential Reference"),
        
        // Sensitive Infrastructure Information
        (r#"(?i)(internal|staging|test|dev|qa|uat)[-.]([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"#, "Internal Hostname"),
        (r#"(?i)(server|host|machine|instance)[_-]?(name|ip|address)[_-]?[=:]\s*['"]([.\w-]+)['"]"#, "Server Information"),
        (r#"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#, "IP Address"),
        
        // Security Misconfiguration
        (r#"(?i)(error|exception|stack\s*trace|debug).*?['"]([^'"]*?)['"]"#, "Error/Debug Information"),
        (r#"(?i)((todo|fixme|hack|xxx|bug|debug):.*)"#, "Developer Comment"),
        (r#"(?i)(error|exception|trace|debug).*log"#, "Log File Reference"),
        
        // Private Keys & Certificates
        (r#"-----BEGIN [A-Z ]+ PRIVATE KEY-----"#, "Private Key Found"),
        (r#"-----BEGIN CERTIFICATE-----"#, "Certificate Found"),
        (r#"(?i)(ssh-rsa|ssh-dss|ecdsa-sha2)[^\s]*"#, "SSH Key"),

        // Security Headers & Cookies
        (r#"(?i)(cookie|set-cookie):\s*[^=]+=([^;]+)"#, "Cookie Information"),
        (r#"(?i)(authorization|auth):\s*[^\s]+"#, "Authorization Header"),
        
        // Version Information
        (r#"(?i)(version|ver)['"]?\s*[:=]\s*['"]([0-9.]+)['"]"#, "Version Information"),
        (r#"(?i)(<meta\s+name=['"](?:generator|version)['"][^>]*>)"#, "Technology Version"),
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

    async fn new(base_url: &str) -> Result<Self> {
        let mut allowed_domains = HashSet::new();
        let base_domain = Url::parse(base_url)?
            .host_str()
            .context("Invalid base URL")?
            .to_string();
        allowed_domains.insert(base_domain);

        let headers = {
            let mut h = HeaderMap::new();
            h.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (compatible; SecurityScanner/1.0)"));
            h.insert(ACCEPT, HeaderValue::from_static("*/*"));
            h
        };

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .default_headers(headers)
            .timeout(Duration::from_secs(TIMEOUT_SECONDS))
            .build()?;

        let rate_limiter = Arc::new(RateLimiter::direct(Quota::per_second(nonzero!(REQUESTS_PER_SECOND))));

        Ok(Scanner {
            client,
            config: ScanConfig {
                max_depth: MAX_DEPTH,
                max_urls_per_domain: MAX_URLS_PER_DOMAIN,
                allowed_domains,
                scan_rules: Self::create_scan_rules(),
                rate_limiter,
            },
            visited: Arc::new(Mutex::new(HashSet::new())),
            findings: Arc::new(Mutex::new(Vec::new())),
            urls_per_domain: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn extract_urls(&self, base_url: &str, content: &str) -> Result<Vec<String>> {
        let base = Url::parse(base_url)?;
        let mut new_urls = Vec::new();
        
        let url_regex = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
        
        for cap in url_regex.captures_iter(content) {
            if let Some(url_match) = cap.get(1) {
                if let Ok(full_url) = base.join(url_match.as_str()) {
                    let url_string = full_url.to_string();
                    let mut visited = self.visited.lock().unwrap();
                    if !visited.contains(&url_string) {
                        visited.insert(url_string.clone());
                        new_urls.push(url_string);
                    }
                }
            }
        }
        
        Ok(new_urls)
    }

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
                let headers = response.headers().clone();
                
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        // Run all analysis
                        self.analyze_advanced_vulnerabilities(url, &body, &headers, depth)?;
                        self.analyze_interactive_vectors(url, &body, depth)?;
                        self.analyze_request_response(url, &headers, &body, depth)?;
                        self.analyze_sensitive_patterns(url, &body, depth)?;
                        
                        if let Ok(extracted_urls) = self.extract_urls(url, &body) {
                            new_urls.extend(extracted_urls);
                        }
                    }
                } else {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Error Response".to_string(),
                        sensitivity: 7,
                        description: format!("Non-200 response code: {}", response.status()),
                        depth,
                        risk_level: RiskLevel::Medium,
                    });
                }
            }

            Ok(new_urls)
        })
    }

    async fn run(&self, start_url: &str) -> Result<Vec<Finding>> {
        let mut pending_urls = vec![start_url.to_string()];
        let mut current_depth = 0;

        while !pending_urls.is_empty() && current_depth < self.config.max_depth {
            println!("Scanning depth {}: {} URLs pending", current_depth, pending_urls.len());
            
            let mut new_urls = Vec::new();
            
            for chunk in pending_urls.chunks(MAX_CONCURRENT_REQUESTS) {
                for url in chunk {
                    if let Ok(urls) = self.scan_url(url, current_depth).await {
                        new_urls.extend(urls);
                    }
                }
            }

            pending_urls = new_urls;
            current_depth += 1;
        }

        Ok(self.findings.lock().unwrap().to_vec())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <https://target_url>", args[0]);
        return Err(ScannerError::ConfigError("Missing target URL".to_string()).into());
    }

    let target_url = &args[1];
    println!("🔍 Starting security scan of {}", target_url);
    println!("⚙️  Configuration:");
    println!("   - Max Depth: {}", MAX_DEPTH);
    println!("   - Rate Limit: {} requests per second", REQUESTS_PER_SECOND);
    println!("   - Timeout: {} seconds", TIMEOUT_SECONDS);
    println!("   - Max Concurrent Requests: {}", MAX_CONCURRENT_REQUESTS);
    
    let scanner = Scanner::new(target_url).await?;
    let findings = scanner.run(target_url).await?;

    println!("\n📊 Scan Results:");
    let critical = findings.iter().filter(|f| f.risk_level == RiskLevel::Critical).count();
    let high = findings.iter().filter(|f| f.risk_level == RiskLevel::High).count();
    
    println!("Found {} total findings:", findings.len());
    println!("🚨 Critical: {}", critical);
    println!("⚠️  High: {}", high);

    if !findings.is_empty() {
        println!("\n🔍 Detailed Findings:");
        for finding in findings {
            println!("\n[{}] {}", finding.risk_level, finding.category);
            println!("URL: {}", finding.url);
            println!("Description: {}", finding.description);
            println!("Sensitivity: {}", finding.sensitivity);
            println!("------------------");
        }
    }

    Ok(())
}