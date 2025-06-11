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