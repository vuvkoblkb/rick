use anyhow::{Context, Result};
use futures::{future::BoxFuture, stream::{self, StreamExt}};
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

    fn analyze_sensitive_patterns(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        let sensitive_patterns = [
            // Kredensial & Kunci API
            (r#"(?i)(api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key)["']?\s*[:=]\s*["']([^"']{8,})["']"#, "API Key/Token Exposure"),
            (r#"(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']([^"']{3,})["']"#, "Password Exposure"),
            (r#"(?i)authorization:\s*bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#, "JWT Token Exposure"),
            
            // Cloud Service Credentials
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            (r"(?i)(aws_secret|aws_key|aws_access)", "AWS Credential Reference"),
            (r"(?i)(azure|microsoft)\s*(key|token|secret)", "Azure Credential Reference"),
            
            // Database Connection Strings
            (r#"(?i)(mongodb|postgres|mysql)(:\/\/|%3A%2F%2F)[^\s<>"']{10,}"#, "Database Connection String"),
            (r#"(?i)jdbc:[a-z]+:\/\/[^\s<>"']+"#, "JDBC Connection String"),
            
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
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        self.analyze_sensitive_patterns(url, &body, depth)?;
                        // Add URL extraction logic here if needed
                    }
                }
            }

            Ok(new_urls)
        })
    }

    async fn run(&self, start_url: &str) -> Result<Vec<Finding>> {
        self.scan_url(start_url, 0).await?;
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
    println!("Starting scan of {}", target_url);
    
    let scanner = Scanner::new(target_url).await?;
    let findings = scanner.run(target_url).await?;

    for finding in findings {
        println!(
            "[{}] {} - {} (Sensitivity: {})",
            finding.risk_level,
            finding.category,
            finding.description,
            finding.sensitivity
        );
    }

    Ok(())
}