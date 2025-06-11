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