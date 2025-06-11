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

impl Scanner {
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

impl Scanner {
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
                    });
                }
            }
        }
        Ok(())
    }