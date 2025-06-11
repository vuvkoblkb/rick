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

        for (pattern, desc, risk) in &advanced_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Advanced Vulnerability".to_string(),
                        sensitivity: 10,
                        description: desc.to_string(),
                        depth,
                        risk_level: risk.clone(),
                    });
                }
            }
        }

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