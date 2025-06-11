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
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use url::Url;

const REQUESTS_PER_SECOND: u32 = 10;
const MAX_DEPTH: u32 = 5;
const TIMEOUT_SECONDS: u64 = 15;
const MAX_URLS_PER_DOMAIN: usize = 1000;

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
struct ScanRule {
    pattern: String,
    sensitivity: u8,
    category: String,
    description: String,
    risk_level: RiskLevel,
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
struct Finding {
    url: String,
    category: String,
    sensitivity: u8,
    description: String,
    depth: u32,
    risk_level: RiskLevel,
}

impl Finding {
    fn calculate_sensitivity(&mut self, base_sensitivity: u8, depth: u32) {
        let depth_factor = (depth as f32 * 0.5).min(3.0);
        self.sensitivity = ((base_sensitivity as f32 + depth_factor).min(10.0)) as u8;
    }
}

struct Scanner {
    client: Client,
    config: ScanConfig,
    visited: Arc<Mutex<HashSet<String>>>,
    findings: Arc<Mutex<Vec<Finding>>>,
    urls_per_domain: Arc<Mutex<HashMap<String, usize>>>,
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

    fn create_scan_rules() -> Vec<ScanRule> {
        vec![

            ScanRule {
                pattern: r"(?i)(/login|/auth|/signin|/signup|/register|/oauth|/sso|/forgot-password|/reset-password|/logout|/password)".to_string(),
                sensitivity: 9,
                category: "Auth".to_string(),
                description: "Authentication endpoint".to_string(),
                risk_level: RiskLevel::Critical,
            },

            ScanRule {
                pattern: r"(?i)(\.env|\.config|\.ini|\.conf|\.yml|\.yaml|\.properties|\.xml|\.json|\.toml|\.cfg|\.settings)$".to_string(),
                sensitivity: 10,
                category: "Config".to_string(),
                description: "Configuration file".to_string(),
                risk_level: RiskLevel::Critical,
            },

            ScanRule {
                pattern: r"(?i)(/db|/database|/sql|/mysql|/pgsql|/mongo|/redis|/storage|/backup|/dump|\.sql|\.db|\.sqlite|/phpmyadmin|/adminer)".to_string(),
                sensitivity: 10,
                category: "DB".to_string(),
                description: "Database related".to_string(),
                risk_level: RiskLevel::Critical,
            },

            ScanRule {
                pattern: r"(?i)(/api/v\d+|/graphql|/graphiql|/swagger|/docs/api|/openapi|/swagger-ui|/api-docs|/rest|/soap)".to_string(),
                sensitivity: 8,
                category: "API".to_string(),
                description: "API endpoint".to_string(),
                risk_level: RiskLevel::High,
            },

            ScanRule {
                pattern: r"(?i)(/dev\b|/test|/stage|/staging|/uat|/beta|/sandbox|/local|/debug|/development|\.test|\.dev|\.local|\.debug)".to_string(),
                sensitivity: 7,
                category: "Dev".to_string(),
                description: "Development environment".to_string(),
                risk_level: RiskLevel::High,
            },

            ScanRule {
                pattern: r"(?i)(/admin|/administrator|/manage|/management|/console|/dashboard|/cp|/panel|/webadmin|/controlpanel|/wp-admin|/admincp)".to_string(),
                sensitivity: 9,
                category: "Admin".to_string(),
                description: "Administrative interface".to_string(),
                risk_level: RiskLevel::Critical,
            },

            ScanRule {
                pattern: r"(?i)(/security|/privacy|/cert|/ssh|/ssl|/tls|/.well-known|/sudo|/su|/root|/.ssh|/.gnupg|/.pgp)".to_string(),
                sensitivity: 8,
                category: "Sec".to_string(),
                description: "Security related".to_string(),
                risk_level: RiskLevel::High,
            },

            ScanRule {
                pattern: r"(?i)(/upload|/download|/file|/document|/docs|/tmp|/temp|/files|/private|/protected|/media|/assets|/static|/downloads)".to_string(),
                sensitivity: 7,
                category: "File".to_string(),
                description: "File operations".to_string(),
                risk_level: RiskLevel::High,
            },

            ScanRule {
                pattern: r"(?i)(/debug|/trace|/status|/health|/info|/log|/logs|/monitor|/stats|/error|/phpinfo|/server-status|\.log$)".to_string(),
                sensitivity: 8,
                category: "Debug".to_string(),
                description: "Debug information".to_string(),
                risk_level: RiskLevel::High,
            },

            ScanRule {
                pattern: r"(?i)(/service|/services|/worker|/job|/task|/queue|/webhook|/callback|/cron|/scheduler|/background|/async)".to_string(),
                sensitivity: 7,
                category: "Service".to_string(),
                description: "Backend service".to_string(),
                risk_level: RiskLevel::High,
            },

            ScanRule {
                pattern: r"(?i)(\.php|\.asp|\.jsp|\.cgi|\.git|\.svn|\.htaccess|\.htpasswd|\.bak|\.old|\.backup|\.swp|\.tmp)".to_string(),
                sensitivity: 9,
                category: "Vuln".to_string(),
                description: "Potential vulnerability".to_string(),
                risk_level: RiskLevel::Critical,
            },

            ScanRule {
                pattern: r"(?i)(password|secret|token|key|credential|admin|root|config|setting|private|backup|dump|database|\.pem|\.key|\.cert)".to_string(),
                sensitivity: 10,
                category: "Data".to_string(),
                description: "Sensitive data exposure".to_string(),
                risk_level: RiskLevel::Critical,
            },

            ScanRule {
                pattern: r"(?i)(/jenkins|/gitlab|/nexus|/sonar|/jira|/confluence|/bamboo|/travis|/circle|/docker|/kubernetes|/k8s)".to_string(),
                sensitivity: 9,
                category: "Infra".to_string(),
                description: "Infrastructure component".to_string(),
                risk_level: RiskLevel::Critical,
            },

            ScanRule {
                pattern: r"(?i)(/wp-|/wordpress|/drupal|/joomla|/magento|/laravel|/symfony|/django|/rails|/spring)".to_string(),
                sensitivity: 8,
                category: "CMS".to_string(),
                description: "CMS/Framework component".to_string(),
                risk_level: RiskLevel::High,
            },

            ScanRule {
                pattern: r"(?i)(/mail|/email|/smtp|/imap|/pop3|/webmail|/newsletter|/subscribe|/contact|/messaging)".to_string(),
                sensitivity: 7,
                category: "Mail".to_string(),
                description: "Email/Communication endpoint".to_string(),
                risk_level: RiskLevel::High,
            },
        ]
    }

    fn scan_url<'a>(&'a self, url: &'a str, depth: u32) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if depth >= self.config.max_depth {
                return Err(ScannerError::MaxDepthReached.into());
            }

            let domain = Url::parse(url)?
                .host_str()
                .context("Invalid URL")?
                .to_string();

            if !self.config.allowed_domains.contains(&domain) {
                return Ok(());
            }

            {
                let mut urls_count = self.urls_per_domain.lock().unwrap();
                let count = urls_count.entry(domain).or_insert(0);
                if *count >= self.config.max_urls_per_domain {
                    return Ok(());
                }
                *count += 1;
            }

            self.config.rate_limiter.until_ready().await;

            if let Ok(response) = self.client.get(url).send().await {
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        if let Ok(new_urls) = self.extract_urls(url, &body) {
                            self.analyze_content(url, &body, depth)?;
                            self.analyze_sensitive_patterns(url, &body, depth)?;

                            for new_url in new_urls {
                                if self.visited.lock().unwrap().insert(new_url.clone()) {
                                    let _ = self.scan_url(&new_url, depth + 1).await;
                                }
                            }
                        }
                    }
                }
            }

            Ok(())
        })
    }

    fn extract_urls(&self, base_url: &str, body: &str) -> Result<HashSet<String>> {
        let mut urls = HashSet::new();
        let document = Html::parse_document(body);
        let selector = Selector::parse("a, link, script, img, iframe").unwrap();
        let base = Url::parse(base_url)?;

        for element in document.select(&selector) {
            for attr in &["href", "src"] {
                if let Some(link) = element.value().attr(attr) {
                    if let Ok(absolute_url) = base.join(link) {
                        urls.insert(absolute_url.to_string());
                    }
                }
            }
        }

        urls.extend(self.extract_js_urls(body));
        Ok(urls)
    }

    fn extract_js_urls(&self, content: &str) -> HashSet<String> {
        let patterns = [
            r#"(?i)["']https?://[^"']+["']"#,
            r#"(?i)url\s*:\s*["']([^"']+)["']"#,
            r#"(?i)endpoint\s*:\s*["']([^"']+)["']"#,
        ];

        let mut urls = HashSet::new();
        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                        urls.insert(m.as_str().trim_matches(|c| c == '"' || c == '\'').to_string());
                    }
                }
            }
        }
        urls
    }

    fn analyze_content(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        for rule in &self.config.scan_rules {
            if let Ok(re) = Regex::new(&rule.pattern) {
                if re.is_match(url) || re.is_match(content) {
                    let mut finding = Finding {
                        url: url.to_string(),
                        category: rule.category.clone(),
                        sensitivity: rule.sensitivity,
                        description: rule.description.clone(),
                        depth,
                        risk_level: rule.risk_level.clone(),
                    };
                    finding.calculate_sensitivity(rule.sensitivity, depth);
                    self.findings.lock().unwrap().push(finding);
                }
            }
        }
        Ok(())
    }

    fn analyze_sensitive_patterns(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        let sensitive_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"[a-zA-Z0-9_-]*api[_-]?key[a-zA-Z0-9_-]*", "API Key"),
            (r"[a-zA-Z0-9_-]*token[a-zA-Z0-9_-]*", "Token"),
            (r"[a-zA-Z0-9_-]*pass(word)?[a-zA-Z0-9_-]*", "Password"),
            (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", "Private Key"),
            (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP Address"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email"),
            (r"mongodb(\+srv)?://[^\s]+", "MongoDB URI"),
            (r"postgres://[^\s]+", "PostgreSQL URI"),
            (r"mysql://[^\s]+", "MySQL URI"),
        ];

        for (pattern, description) in &sensitive_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    let finding = Finding {
                        url: url.to_string(),
                        category: "Leak".to_string(),
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

    async fn run(&self, start_url: &str) -> Result<Vec<Finding>> {
        self.scan_url(start_url, 0).await?;
        Ok(self.findings.lock().unwrap().to_vec())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(ScannerError::ConfigError("Usage: <https://target_url>".to_string()).into());
    }

    let target_url = &args[1];
    let scanner = Scanner::new(target_url).await?;
    let findings = scanner.run(target_url).await?;

    for finding in findings {
        println!("[{}][{}] {} (S:{}/D:{}) - {}", 
            finding.risk_level,
            finding.category,
            finding.url,
            finding.sensitivity,
            finding.depth,
            finding.description
        );
    }

    Ok(())
}
