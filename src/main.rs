use anyhow::Result;
use futures::future::BoxFuture;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use nonzero_ext::*;
use regex::Regex;
use reqwest::{
    header::{HeaderMap, HeaderValue, ACCEPT},
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
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

    fn analyze_zero_day_vectors(&self, url: &str, content: &str, response_headers: &HeaderMap, depth: u32) -> Result<()> {
        let zero_day_patterns = [
            // HTTP Request Smuggling
            (r#"(?i)(transfer-encoding:\s*chunked.*content-length:|content-length:.*transfer-encoding:\s*chunked)"#, "HTTP Smuggling Attack Vector", RiskLevel::Critical),
            
            // HTTP Request Splitting
            (r#"(?i)([\r\n][\r\n]|%0d%0a%0d%0a|%0D%0A%0D%0A)"#, "HTTP Splitting Attack Vector", RiskLevel::Critical),
            
            // Advanced Cache Poisoning
            (r#"(?i)(x-forwarded-host|x-forwarded-scheme|x-forwarded-proto|x-host|x-original-url|x-rewrite-url)"#, "Cache Poisoning Vector", RiskLevel::Critical),
            
            // Web Cache Deception
            (r#"(?i)(/\.(?:css|js|txt|jpg|pdf)/.*/(?:conf|config|admin|user|account))"#, "Cache Deception Path", RiskLevel::Critical),
            
            // Mass Assignment
            (r#"(?i)(role|admin|permission|isadmin|access_level)\s*[=:]\s*(?:true|1|yes)"#, "Mass Assignment Vulnerability", RiskLevel::Critical),
            
            // Server-Side Prototype Pollution
            (r#"(?i)(__proto__|constructor|prototype).*?[=:]\s*\{.*?\}"#, "Server-Side Prototype Pollution", RiskLevel::Critical),
        ];

        for (pattern, desc, risk) in &zero_day_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) || response_headers.iter().any(|(k, v)| re.is_match(&format!("{}:{}", k.as_str(), v.to_str().unwrap_or("")))) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Zero-Day Vector".to_string(),
                        sensitivity: 10,
                        description: desc.to_string(),
                        depth,
                        risk_level: risk.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn analyze_advanced_injections(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        let injection_patterns = [
            // Sophisticated SQL Injection
            (r#"(?i)(\%27|\'|\-\-|\%23|\#|\%3B|;)\s*(and|or|union|select|insert|update|delete|drop|alter|create|rename|truncate|backup|restore)\s*(\%27|\'|\-\-|\%23|\#|\%3B|;)"#, "Advanced SQL Injection Pattern"),
            
            // NoSQL Advanced Injection
            (r#"(?i)(\{|\[)\s*(\$where|\$regex|\$ne|\$gt|\$lt|\$exists|\$in|\$nin|\$all|\$size|\$mod|\$type|\$not)\s*:"#, "NoSQL Advanced Injection Pattern"),
            
            // GraphQL Introspection
            (r#"(?i)(query\s*{\s*__schema\s*{\s*types\s*{\s*name|mutation\s*{\s*fields\s*{\s*name)"#, "GraphQL Introspection Attack"),
            
            // LDAP Advanced Injection
            (r#"(?i)(\*|\(|\)|\||&|!)(objectClass|cn|ou|dc|dn|uid)=.*?\((cn|ou|dc|dn|uid)="#, "LDAP Injection Attack"),
            
            // MongoDB Injection
            (r#"(?i)(\{|\[)\s*(true|false|1|0)\s*:\s*1"#, "MongoDB Injection Attack"),
            
            // Advanced XPath Injection
            (r#"(?i)(/\*|\*/|\[|\]|\||\(|\)|=|and|or|not)\s*(descendant::|ancestor::|following::|preceding::)"#, "XPath Injection Attack"),
            
            // Advanced OS Command Injection
            (r#"(?i)(`|\$\(|\|\||&&|\;|\%0A|\n|\r|\%0D)\s*(cat|tac|nl|more|less|head|tail|od|strings|curl|wget|fetch|lwp-download|lynx|w3m)"#, "OS Command Injection Attack"),
            
            // Advanced Format String Injection
            (r#"(?i)(%[0-9]*\$[dioxXucsfeEgGpn]|%[0-9.]*l?[dioxXucsfeEgGpn])"#, "Format String Attack"),
            
            // Template Injection
            (r#"(?i)(\{\{.*?\}\}|\${.*?}|\#{.*?}|<%.*?%>|\$\{.*?\})"#, "Template Injection Attack"),
        ];

        for (pattern, desc) in &injection_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Advanced Injection".to_string(),
                        sensitivity: 10,
                        description: format!("Critical: {} detected", desc),
                        depth,
                        risk_level: RiskLevel::Critical,
                    });
                }
            }
        }
        Ok(())
    }

    fn analyze_crypto_vulnerabilities(&self, content: &str, url: &str, depth: u32) -> Result<()> {
        let crypto_patterns = [
            // Weak Crypto
            (r#"(?i)(MD5|SHA1|RC4|DES|ECB)"#, "Weak Cryptographic Algorithm"),
            
            // Hardcoded Crypto Keys
            (r#"(?i)(private_key|secret_key|encryption_key)\s*=\s*['"][0-9a-fA-F]{16,}['"]"#, "Hardcoded Cryptographic Key"),
            
            // Insecure Random
            (r#"(?i)(Math\.random|rand\(|random\()"#, "Insecure Random Number Generator"),
            
            // Weak SSL/TLS Configuration
            (r#"(?i)(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)"#, "Weak SSL/TLS Protocol"),
            
            // Null Cipher
            (r#"(?i)(NULL-SHA|NULL-MD5|aNULL|eNULL)"#, "Null Cipher Usage"),
        ];

        for (pattern, desc) in &crypto_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Cryptographic Vulnerability".to_string(),
                        sensitivity: 9,
                        description: desc.to_string(),
                        depth,
                        risk_level: RiskLevel::Critical,
                    });
                }
            }
        }
        Ok(())
    }

    fn analyze_obfuscation_techniques(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        let obfuscation_patterns = [
            // JavaScript Obfuscation
            (r#"(?i)(eval|atob|btoa|escape|unescape|encodeURI|decodeURI|Function)\s*\(.*?(fromCharCode|String\.fromCharCode)"#, "JavaScript Obfuscation Technique"),
            
            // Base64 Encoded Payloads
            (r#"(?i)(eyJ|YTo|PD94|PHN2|PHNj|PGh0|ZXZh|amF2|ZnVu|Oi8v)[a-zA-Z0-9+/]{30,}={0,2}"#, "Base64 Encoded Payload"),
            
            // URL Encoded Payloads
            (r#"(%[0-9A-Fa-f]{2}){10,}"#, "Complex URL Encoded Content"),
            
            // Unicode Escape Sequences
            (r#"\\u[0-9A-Fa-f]{4}(\\u[0-9A-Fa-f]{4}){3,}"#, "Unicode Escape Sequence Chain"),
            
            // Hex Encoded Content
            (r#"\\x[0-9A-Fa-f]{2}(\\x[0-9A-Fa-f]{2}){10,}"#, "Hex Encoded Content"),
            
            // JavaScript String Concatenation
            (r#"(?i)(['"])\s*\+\s*\1"#, "String Concatenation Obfuscation"),
            
            // Advanced Charcode Array
            (r#"\[[0-9,\s]+\]\.map\(String\.fromCharCode\)"#, "Charcode Array Obfuscation"),
            
            // Decode Chains
            (r#"(?i)(decode|decrypt|deobfuscate|unescape)\s*\(\s*(decode|decrypt|deobfuscate|unescape)"#, "Multiple Decode Chain"),
        ];

        for (pattern, desc) in &obfuscation_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Obfuscation Detection".to_string(),
                        sensitivity: 9,
                        description: format!("{} - Potential malicious payload", desc),
                        depth,
                        risk_level: RiskLevel::High,
                    });
                }
            }
        }
        Ok(())
    }

    fn analyze_advanced_xss(&self, url: &str, content: &str, depth: u32) -> Result<()> {
        let xss_patterns = [
            // DOM XSS
            (r#"(?i)(document\.(location|referrer|cookie|write|documentElement)|window\.(location|name|onload|history))"#, "DOM-based XSS Vector"),
            
            // Mutation XSS
            (r#"(?i)(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval)\s*="#, "Mutation-based XSS"),
            
            // Event Handler XSS
            (r#"(?i)on(mouseenter|mouseleave|mouseover|mouseout|mousedown|mouseup|click|dblclick|keydown|keyup|keypress|submit|load|unload|abort|error|resize|scroll|select|change|focus|blur)"#, "Event Handler XSS"),
            
            // Advanced Attribute XSS
            (r#"(?i)(javascript|data|vbscript):\s*([^\"\'>;]*)(alert|confirm|prompt|eval|setTimeout|setInterval|Function|expression)"#, "Advanced Attribute XSS"),
            
            // Template Injection XSS
            (r#"(?i)\{\{.*?(constructor|prototype|__proto__|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__)"#, "Template Injection XSS"),
            
            // AngularJS XSS
            (r#"(?i)ng-[a-z]+=".*?(constructor|prototype|window|document|alert|confirm|prompt|eval)"#, "AngularJS XSS"),
            
            // SVG XSS
            (r#"(?i)<svg[^>]*>\s*<(?:script|animate|set|use|image)"#, "SVG-based XSS"),
            
            // XML XSS
            (r#"(?i)<!\[CDATA\[.*?(alert|confirm|prompt|eval|setTimeout|setInterval|Function)"#, "XML CDATA XSS"),
            
            // CSS XSS
            (r#"(?i)expression\s*\(|behavior\s*:|microsoft\s*:\s*expression"#, "CSS Expression XSS"),
        ];

        for (pattern, desc) in &xss_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "Advanced XSS".to_string(),
                        sensitivity: 10,
                        description: desc.to_string(),
                        depth,
                        risk_level: RiskLevel::Critical,
                    });
                }
            }
        }
        Ok(())
    }

    fn analyze_api_vulnerabilities(&self, url: &str, content: &str, response_headers: &HeaderMap, depth: u32) -> Result<()> {
        let api_patterns = [
            // GraphQL Vulnerabilities
            (r#"(?i)(query|mutation)\s*{\s*.*?\s*{\s*.*?\s*}"#, "GraphQL Query Pattern"),
            (r#"(?i)__schema\s*{\s*types\s*{\s*name"#, "GraphQL Schema Exposure"),
            
            // REST API Vulnerabilities
            (r#"(?i)/api/v[0-9]+/"#, "API Version Exposure"),
            (r#"(?i)/swagger\b|/api-docs\b"#, "API Documentation Exposure"),
            
            // JWT Issues
            (r#"(?i)eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"#, "JWT Token Exposure"),
            
            // API Key Exposure
            (r#"(?i)(api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{16,}['"]"#, "API Key Exposure"),
            
            // CORS Misconfiguration
            (r#"(?i)Access-Control-Allow-(Origin|Methods|Headers):\s*\*"#, "Permissive CORS Policy"),
            
            // Rate Limiting Headers
            (r#"(?i)(X-Rate-Limit|RateLimit-)"#, "Rate Limit Information Exposure"),
        ];

        for (pattern, desc) in &api_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) || response_headers.iter().any(|(k, v)| re.is_match(&format!("{}:{}", k.as_str(), v.to_str().unwrap_or("")))) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: "API Security".to_string(),
                        sensitivity: 8,
                        description: desc.to_string(),
                        depth,
                        risk_level: RiskLevel::High,


pub fn add_scan_rule(&mut self, rule: ScanRule) {
    self.config.scan_rules.push(rule);
}

pub fn add_scan_rules(&mut self, rules: Vec<ScanRule>) {
    for rule in rules {
        self.config.scan_rules.push(rule);
    }
}

fn run_custom_rules(&self, url: &str, content: &str, headers: &HeaderMap, depth: u32) -> Result<()> {
    if !self.config.scan_rules.is_empty() {
        for rule in &self.config.scan_rules {
            if let Ok(re) = Regex::new(&rule.pattern) {
                // Check content
                if re.is_match(content) {
                    self.findings.lock().unwrap().push(Finding {
                        url: url.to_string(),
                        category: rule.category.clone(),
                        sensitivity: rule.sensitivity,
                        description: format!("{} - Custom Rule Match", rule.description),
                        depth,
                        risk_level: rule.risk_level.clone(),
                    });
                }

                // Check headers
                for (key, value) in headers.iter() {
                    if re.is_match(&format!("{}:{}", key.as_str(), value.to_str().unwrap_or(""))) {
                        self.findings.lock().unwrap().push(Finding {
                            url: url.to_string(),
                            category: rule.category.clone(),
                            sensitivity: rule.sensitivity,
                            description: format!("{} - Found in Headers", rule.description),
                            depth,
                            risk_level: rule.risk_level.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

    fn new(target_url: &str) -> Result<Self> {
        let url = Url::parse(target_url)?;
        let domain = url.host_str().ok_or_else(|| ScannerError::ConfigError("Invalid URL".into()))?;
        
        let mut allowed_domains = HashSet::new();
        allowed_domains.insert(domain.to_string());

        let client = Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECONDS))
            .user_agent("Mozilla/5.0 (compatible; RickScanner/1.0)")
            .default_headers({
                let mut headers = HeaderMap::new();
                headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
                headers
            })
            .build()?;

        let config = ScanConfig {
            max_depth: MAX_DEPTH,
            max_urls_per_domain: MAX_URLS_PER_DOMAIN,
            allowed_domains,
            scan_rules: Vec::new(),
            rate_limiter: Arc::new(RateLimiter::direct(Quota::per_second(nonzero!(REQUESTS_PER_SECOND)))),
        };

        Ok(Scanner {
            client,
            config,
            visited: Arc::new(Mutex::new(HashSet::new())),
            findings: Arc::new(Mutex::new(Vec::new())),
            urls_per_domain: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn scan(&self, start_url: &str) -> Result<Vec<Finding>> {
        let mut urls_to_scan = vec![start_url.to_string()];
        let mut scanned_urls = HashSet::new();
        
        while let Some(url) = urls_to_scan.pop() {
            if !scanned_urls.contains(&url) {
                scanned_urls.insert(url.clone());
                
                // Rate limiting
                self.config.rate_limiter.until_ready().await;
                
                if let Ok(new_urls) = self.scan_url(&url, 0).await {
                    urls_to_scan.extend(new_urls);
                }
            }
        }
        
        Ok(self.findings.lock().unwrap().clone())
    }

    fn scan_url<'a>(&'a self, url: &'a str, depth: u32) -> BoxFuture<'a, Result<Vec<String>>> {
        Box::pin(async move {
            let mut new_urls = Vec::new();

            // Check depth limit
            if depth >= self.config.max_depth {
                return Ok(new_urls);
            }

            // Check if URL was already visited
            if !self.visited.lock().unwrap().insert(url.to_string()) {
                return Ok(new_urls);
            }

            let domain = Url::parse(url)
    .ok()
    .and_then(|u| u.host_str().map(|h| h.to_string()))
    .unwrap_or_default();

{
    let mut domain_counts = self.urls_per_domain.lock().unwrap();
    let urls_count = domain_counts.entry(domain.clone()).or_insert(0);
    if *urls_count >= self.config.max_urls_per_domain {
        return Ok(new_urls);
    }
    *urls_count += 1;
}

            // Perform the actual scan
            if let Ok(response) = self.client.get(url).send().await {
                let headers = response.headers().clone();
                
                if response.status().is_success() {
    if let Ok(body) = response.text().await {
        // Run custom rules first
        self.run_custom_rules(url, &body, &headers, depth)?;

        // Run all built-in analysis
        self.analyze_advanced_vulnerabilities(url, &body, &headers, depth)?;
        self.analyze_zero_day_vectors(url, &body, &headers, depth)?;
        self.analyze_advanced_injections(url, &body, depth)?;
        self.analyze_obfuscation_techniques(url, &body, depth)?;
        self.analyze_advanced_xss(url, &body, depth)?;
        self.analyze_api_vulnerabilities(url, &body, &headers, depth)?;
        self.analyze_crypto_vulnerabilities(&body, url, depth)?;
                        
                        // Extract and filter new URLs
                        if let Ok(extracted_urls) = self.extract_urls(url, &body) {
                            new_urls.extend(extracted_urls.into_iter().filter(|u| {
                                if let Ok(parsed) = Url::parse(u) {
                                    if let Some(host) = parsed.host_str() {
                                        return self.config.allowed_domains.contains(host);
                                    }
                                }
                                false
                            }));
                        }
                    }
                }
            }

            Ok(new_urls)
        })
    }

    fn extract_urls(&self, base_url: &str, content: &str) -> Result<Vec<String>> {
        let mut urls = Vec::new();
        let base = Url::parse(base_url)?;
        
        // Regular expression for URL extraction
        let url_patterns = [
            // HTML href links
            r#"href\s*=\s*["']([^"']+)["']"#,
            // HTML src attributes
            r#"src\s*=\s*["']([^"']+)["']"#,
            // JavaScript URLs
            r#"(?:url|URL)\s*\(\s*["']([^"']+)["']\s*\)"#,
            // XML URLs
            r#"(?:uri|URI)\s*=\s*["']([^"']+)["']"#,
            // General URLs
            r#"https?://[^\s<>"'{}|\\^[\]`]++"#,
        ];

        for pattern in &url_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(url_match) = cap.get(1).or_else(|| cap.get(0)) {
                        if let Ok(absolute_url) = base.join(url_match.as_str()) {
                            urls.push(absolute_url.to_string());
                        }
                    }
                }
            }
        }

        Ok(urls)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_url>", args[0]);
        std::process::exit(1);
    }

    let target_url = &args[1];
    println!("Starting security scan of: {}", target_url);

    // Create scanner with custom rules
    let mut scanner = Scanner::new(target_url)?;

    // Add default custom rules
    let default_rules = vec![
        ScanRule {
            pattern: r#"(?i)(secret|password|api[_-]?key)\s*=\s*['"][^'"]{8,}['"]"#.to_string(),
            sensitivity: 9,
            category: "Custom Secret Detection".to_string(),
            description: "Potential hardcoded secret detected".to_string(),
            risk_level: RiskLevel::Critical,
        },
        ScanRule {
            pattern: r#"(?i)(SELECT|INSERT|UPDATE|DELETE).*?(WHERE|FROM|INTO|VALUES)"#.to_string(),
            sensitivity: 10,
            category: "Custom SQL Injection Detection".to_string(),
            description: "Potential SQL query exposure".to_string(),
            risk_level: RiskLevel::Critical,
        },
        ScanRule {
            pattern: r#"(?i)\.\./(.*?)/(.*?)/"#.to_string(),
            sensitivity: 8,
            category: "Custom Path Traversal Detection".to_string(),
            description: "Potential directory traversal vulnerability".to_string(),
            risk_level: RiskLevel::High,
        },
        ScanRule {
            pattern: r#"(?i)(admin|root|superuser|sudo)\s*=\s*(true|1|yes)"#.to_string(),
            sensitivity: 9,
            category: "Custom Privilege Escalation Detection".to_string(),
            description: "Potential privilege escalation vector".to_string(),
            risk_level: RiskLevel::Critical,
        },
        ScanRule {
            pattern: r#"(?i)(auth|token|jwt)\.sign\s*\([^\)]*\)"#.to_string(),
            sensitivity: 8,
            category: "Custom Authentication Bypass Detection".to_string(),
            description: "Potential authentication bypass vector".to_string(),
            risk_level: RiskLevel::High,
        }
    ];

    // Add all default rules
    scanner.add_scan_rules(default_rules);

    // Start scanning
    let findings = scanner.scan(target_url).await?;

    // Group findings by risk level
    let findings_by_risk = findings
        .into_iter()
        .fold(HashMap::new(), |mut acc, finding| {
            acc.entry(finding.risk_level.clone())
                .or_insert_with(Vec::new)
                .push(finding);
            acc
        });

    // Print findings sorted by risk level
    for risk_level in &[RiskLevel::Critical, RiskLevel::High, RiskLevel::Medium, RiskLevel::Low, RiskLevel::Info] {
        if let Some(level_findings) = findings_by_risk.get(risk_level) {
            println!("\n{} Level Findings:", risk_level);
            for finding in level_findings {
                println!("\nURL: {}", finding.url);
                println!("Category: {}", finding.category);
                println!("Description: {}", finding.description);
                println!("Depth: {}", finding.depth);
            }
        }
    }

    Ok(())
}