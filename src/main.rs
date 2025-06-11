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