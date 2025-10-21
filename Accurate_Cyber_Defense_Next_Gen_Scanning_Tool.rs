use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local, Timelike};
use std::str::FromStr;

// Configuration structures
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DatabaseConfig {
    path: String,
    max_history: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitoringConfig {
    packet_count: usize,
    timeout: u64,
    alert_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelegramConfig {
    token: String,
    chat_id: String,
    poll_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanningConfig {
    max_threads: usize,
    default_ports: String,
    timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrafficConfig {
    max_packets: usize,
    packet_size: usize,
    delay: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    database: DatabaseConfig,
    monitoring: MonitoringConfig,
    telegram: TelegramConfig,
    scanning: ScanningConfig,
    traffic: TrafficConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: DatabaseConfig {
                path: "cyber_tool.db".to_string(),
                max_history: 10000,
            },
            monitoring: MonitoringConfig {
                packet_count: 1000,
                timeout: 30,
                alert_threshold: 100,
            },
            telegram: TelegramConfig {
                token: "".to_string(),
                chat_id: "".to_string(),
                poll_interval: 2,
            },
            scanning: ScanningConfig {
                max_threads: 100,
                default_ports: "1-1000".to_string(),
                timeout: 2,
            },
            traffic: TrafficConfig {
                max_packets: 10000,
                packet_size: 1024,
                delay: 0.01,
            },
        }
    }
}

// Database models
#[derive(Debug, Clone)]
struct IPAddress {
    ip: String,
    description: String,
    created_at: SystemTime,
    is_active: bool,
}

#[derive(Debug, Clone)]
struct Threat {
    ip: String,
    threat_type: String,
    severity: u8,
    description: String,
    timestamp: SystemTime,
    packet_count: u64,
}

#[derive(Debug, Clone)]
struct CommandHistory {
    command: String,
    timestamp: SystemTime,
    user: String,
}

#[derive(Debug, Clone)]
struct MonitoringResult {
    ip: String,
    port: Option<u16>,
    protocol: String,
    packet_count: u64,
    threat_detected: bool,
    timestamp: SystemTime,
}

#[derive(Debug, Clone)]
struct ScanResult {
    ip: String,
    port: u16,
    state: String,
    service: String,
    timestamp: SystemTime,
}

#[derive(Debug, Clone)]
struct Report {
    report_type: String,
    period: String,
    content: String,
    generated_at: SystemTime,
}

// Database Manager
struct DatabaseManager {
    path: String,
    connection: rusqlite::Connection,
}

impl DatabaseManager {
    fn new(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(path)?;
        
        // Initialize tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packet_count INTEGER DEFAULT 0
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user TEXT DEFAULT 'console'
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS monitoring_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER,
                protocol TEXT,
                packet_count INTEGER,
                threat_detected BOOLEAN DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER,
                state TEXT,
                service TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                period TEXT NOT NULL,
                content TEXT,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        
        Ok(Self {
            path: path.to_string(),
            connection: conn,
        })
    }
    
    fn add_ip(&self, ip: &str, description: &str) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "INSERT OR IGNORE INTO ip_addresses (ip, description) VALUES (?, ?)",
            &[ip, description],
        )?;
        Ok(())
    }
    
    fn remove_ip(&self, ip: &str) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "DELETE FROM ip_addresses WHERE ip = ?",
            &[ip],
        )?;
        Ok(())
    }
    
    fn get_all_ips(&self) -> Result<Vec<IPAddress>, rusqlite::Error> {
        let mut stmt = self.connection.prepare(
            "SELECT ip, description, created_at, is_active FROM ip_addresses WHERE is_active = 1"
        )?;
        
        let ip_iter = stmt.query_map([], |row| {
            Ok(IPAddress {
                ip: row.get(0)?,
                description: row.get(1)?,
                created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(2)? as u64),
                is_active: row.get(3)?,
            })
        })?;
        
        let mut ips = Vec::new();
        for ip in ip_iter {
            ips.push(ip?);
        }
        Ok(ips)
    }
    
    fn add_threat(&self, threat: &Threat) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "INSERT INTO threats (ip, threat_type, severity, description, packet_count) VALUES (?, ?, ?, ?, ?)",
            &[
                &threat.ip,
                &threat.threat_type,
                &(threat.severity as i64),
                &threat.description,
                &(threat.packet_count as i64),
            ],
        )?;
        Ok(())
    }
    
    fn get_threats(&self, ip: Option<&str>, limit: i64) -> Result<Vec<Threat>, rusqlite::Error> {
        let query = if let Some(ip_addr) = ip {
            "SELECT ip, threat_type, severity, description, timestamp, packet_count FROM threats WHERE ip = ? ORDER BY timestamp DESC LIMIT ?"
        } else {
            "SELECT ip, threat_type, severity, description, timestamp, packet_count FROM threats ORDER BY timestamp DESC LIMIT ?"
        };
        
        let mut stmt = self.connection.prepare(query)?;
        
        let threat_iter = if let Some(ip_addr) = ip {
            stmt.query_map(&[ip_addr, &limit], |row| {
                Ok(Threat {
                    ip: row.get(0)?,
                    threat_type: row.get(1)?,
                    severity: row.get(2)?,
                    description: row.get(3)?,
                    timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(4)? as u64),
                    packet_count: row.get(5)?,
                })
            })?
        } else {
            stmt.query_map(&[&limit], |row| {
                Ok(Threat {
                    ip: row.get(0)?,
                    threat_type: row.get(1)?,
                    severity: row.get(2)?,
                    description: row.get(3)?,
                    timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(4)? as u64),
                    packet_count: row.get(5)?,
                })
            })?
        };
        
        let mut threats = Vec::new();
        for threat in threat_iter {
            threats.push(threat?);
        }
        Ok(threats)
    }
    
    fn add_command_history(&self, command: &str, user: &str) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "INSERT INTO command_history (command, user) VALUES (?, ?)",
            &[command, user],
        )?;
        Ok(())
    }
    
    fn get_command_history(&self, limit: i64) -> Result<Vec<CommandHistory>, rusqlite::Error> {
        let mut stmt = self.connection.prepare(
            "SELECT command, timestamp, user FROM command_history ORDER BY timestamp DESC LIMIT ?"
        )?;
        
        let history_iter = stmt.query_map(&[&limit], |row| {
            Ok(CommandHistory {
                command: row.get(0)?,
                timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(1)? as u64),
                user: row.get(2)?,
            })
        })?;
        
        let mut history = Vec::new();
        for cmd in history_iter {
            history.push(cmd?);
        }
        Ok(history)
    }
}

// Network Monitor
struct NetworkMonitor {
    db: Arc<DatabaseManager>,
    monitoring: Arc<Mutex<bool>>,
    monitored_ips: Arc<Mutex<HashSet<String>>>,
    packet_stats: Arc<Mutex<HashMap<String, PacketStats>>>,
}

#[derive(Debug, Clone)]
struct PacketStats {
    total_packets: u64,
    last_seen: u64,
    syn_count: u64,
    ports_scanned: HashSet<u16>,
    http_requests: u64,
    udp_packets: u64,
    icmp_packets: u64,
}

impl Default for PacketStats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            last_seen: 0,
            syn_count: 0,
            ports_scanned: HashSet::new(),
            http_requests: 0,
            udp_packets: 0,
            icmp_packets: 0,
        }
    }
}

impl NetworkMonitor {
    fn new(db: Arc<DatabaseManager>) -> Self {
        Self {
            db,
            monitoring: Arc::new(Mutex::new(false)),
            monitored_ips: Arc::new(Mutex::new(HashSet::new())),
            packet_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    fn start_monitoring(&self, target_ip: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ip) = target_ip {
            self.monitored_ips.lock().unwrap().insert(ip.to_string());
        }
        
        *self.monitoring.lock().unwrap() = true;
        
        let monitoring = self.monitoring.clone();
        let monitored_ips = self.monitored_ips.clone();
        let packet_stats = self.packet_stats.clone();
        let db = self.db.clone();
        
        thread::spawn(move || {
            while *monitoring.lock().unwrap() {
                // Simulate packet analysis (in real implementation, use pcap or similar)
                thread::sleep(Duration::from_secs(5));
                
                // Check for threats based on collected statistics
                if let Ok(stats) = packet_stats.lock() {
                    for (ip, stat) in stats.iter() {
                        // Check for port scanning
                        if stat.ports_scanned.len() > 10 {
                            let threat = Threat {
                                ip: ip.clone(),
                                threat_type: "PORT_SCAN".to_string(),
                                severity: 2,
                                description: format!("Multiple ports scanned: {}", stat.ports_scanned.len()),
                                timestamp: SystemTime::now(),
                                packet_count: stat.total_packets,
                            };
                            let _ = db.add_threat(&threat);
                        }
                        
                        // Check for DoS attacks
                        if stat.total_packets > 1000 {
                            let threat = Threat {
                                ip: ip.clone(),
                                threat_type: "DOS_ATTACK".to_string(),
                                severity: 3,
                                description: format!("High packet rate: {} packets", stat.total_packets),
                                timestamp: SystemTime::now(),
                                packet_count: stat.total_packets,
                            };
                            let _ = db.add_threat(&threat);
                        }
                    }
                }
                
                // Clean old statistics periodically
                Self::clean_old_stats(&packet_stats);
            }
        });
        
        println!("Network monitoring started for IPs: {:?}", self.monitored_ips.lock().unwrap());
        Ok(())
    }
    
    fn stop_monitoring(&self) {
        *self.monitoring.lock().unwrap() = false;
        println!("Network monitoring stopped");
    }
    
    fn clean_old_stats(packet_stats: &Arc<Mutex<HashMap<String, PacketStats>>>) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timeout = 300; // 5 minutes
        
        if let Ok(mut stats) = packet_stats.lock() {
            stats.retain(|_, stat| current_time - stat.last_seen <= timeout);
        }
    }
    
    fn get_ip_location(&self, _ip: &str) -> String {
        // In a real implementation, use a GeoIP database
        "Location feature requires GeoIP database".to_string()
    }
}

// Network Scanner
struct NetworkScanner {
    db: Arc<DatabaseManager>,
    scanning: Arc<Mutex<bool>>,
}

impl NetworkScanner {
    fn new(db: Arc<DatabaseManager>) -> Self {
        Self {
            db,
            scanning: Arc::new(Mutex::new(false)),
        }
    }
    
    fn ping_ip(&self, ip: &str) -> bool {
        let output = if cfg!(target_os = "windows") {
            Command::new("ping")
                .args(&["-n", "1", ip])
                .output()
        } else {
            Command::new("ping")
                .args(&["-c", "1", ip])
                .output()
        };
        
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
    
    fn scan_ports(&self, ip: &str, ports: &str) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
        if *self.scanning.lock().unwrap() {
            return Err("Another scan is in progress".into());
        }
        
        *self.scanning.lock().unwrap() = true;
        
        let mut results = Vec::new();
        
        // Parse port range (simplified - in real implementation parse ranges like "1-1000")
        let port_list: Vec<u16> = if ports == "1-1000" {
            (1..=1000).collect()
        } else if ports == "1-65535" {
            (1..=100).collect() // Limit for demo
        } else {
            // Parse common ports
            vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995]
        };
        
        for &port in &port_list {
            let address = format!("{}:{}", ip, port);
            if let Ok(_stream) = TcpStream::connect_timeout(
                &address.parse().unwrap(),
                Duration::from_secs(2)
            ) {
                let result = ScanResult {
                    ip: ip.to_string(),
                    port,
                    state: "open".to_string(),
                    service: Self::guess_service(port),
                    timestamp: SystemTime::now(),
                };
                
                // Save to database
                let _ = self.db.connection.execute(
                    "INSERT INTO scan_results (ip, port, state, service) VALUES (?, ?, ?, ?)",
                    &[&result.ip, &(result.port as i64), &result.state, &result.service],
                );
                
                results.push(result);
            }
        }
        
        *self.scanning.lock().unwrap() = false;
        Ok(results)
    }
    
    fn guess_service(port: u16) -> String {
        match port {
            21 => "ftp".to_string(),
            22 => "ssh".to_string(),
            23 => "telnet".to_string(),
            25 => "smtp".to_string(),
            53 => "dns".to_string(),
            80 => "http".to_string(),
            110 => "pop3".to_string(),
            143 => "imap".to_string(),
            443 => "https".to_string(),
            465 => "smtps".to_string(),
            587 => "smtp".to_string(),
            993 => "imaps".to_string(),
            995 => "pop3s".to_string(),
            _ => "unknown".to_string(),
        }
    }
    
    fn deep_scan(&self, ip: &str) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
        self.scan_ports(ip, "1-65535")
    }
    
    fn quick_scan(&self, ip: &str) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
        self.scan_ports(ip, "common")
    }
}

// Traffic Generator
struct TrafficGenerator {
    generating: Arc<Mutex<bool>>,
    stats: Arc<Mutex<TrafficStats>>,
}

#[derive(Debug, Clone)]
struct TrafficStats {
    packets_sent: u64,
    bytes_sent: u64,
    start_time: Option<SystemTime>,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            bytes_sent: 0,
            start_time: None,
        }
    }
}

impl TrafficGenerator {
    fn new() -> Self {
        Self {
            generating: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(TrafficStats::default())),
        }
    }
    
    fn udp_flood(&self, target_ip: &str, target_port: u16, duration: u64, packet_size: usize) -> Result<String, Box<dyn std::error::Error>> {
        if *self.generating.lock().unwrap() {
            return Err("Another traffic generation in progress".into());
        }
        
        *self.generating.lock().unwrap() = true;
        *self.stats.lock().unwrap() = TrafficStats {
            packets_sent: 0,
            bytes_sent: 0,
            start_time: Some(SystemTime::now()),
        };
        
        let generating = self.generating.clone();
        let stats = self.stats.clone();
        let target = format!("{}:{}", target_ip, target_port);
        
        thread::spawn(move || {
            let end_time = SystemTime::now() + Duration::from_secs(duration);
            let data = vec![0u8; packet_size];
            
            if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                while SystemTime::now() < end_time && *generating.lock().unwrap() {
                    if let Ok(_) = socket.send_to(&data, &target) {
                        let mut stats_lock = stats.lock().unwrap();
                        stats_lock.packets_sent += 1;
                        stats_lock.bytes_sent += packet_size as u64;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
            *generating.lock().unwrap() = false;
        });
        
        Ok(format!("UDP flood started against {} for {}s", target, duration))
    }
    
    fn stop_traffic(&self) -> String {
        *self.generating.lock().unwrap() = false;
        "Traffic generation stopped".to_string()
    }
    
    fn get_stats(&self) -> TrafficStats {
        self.stats.lock().unwrap().clone()
    }
}

// Curl Commands
struct CurlCommands;

impl CurlCommands {
    fn curl_simple(url: &str) -> Result<String, Box<dyn std::error::Error>> {
        let response = minreq::get(url).send()?;
        Ok(format!("Status: {}\nHeaders: {:?}\n\nFirst 500 chars:\n{}", 
                  response.status_code,
                  response.headers,
                  response.as_str().unwrap_or("")[..500.min(response.as_str().unwrap_or("").len())].to_string()))
    }
    
    fn curl_head(url: &str) -> Result<String, Box<dyn std::error::Error>> {
        let response = minreq::head(url).send()?;
        Ok(format!("Status: {}\nHeaders: {:?}", response.status_code, response.headers))
    }
    
    // Additional curl methods can be implemented similarly
}

// Report Generator
struct ReportGenerator {
    db: Arc<DatabaseManager>,
}

impl ReportGenerator {
    fn new(db: Arc<DatabaseManager>) -> Self {
        Self { db }
    }
    
    fn generate_daily_report(&self) -> Result<String, Box<dyn std::error::Error>> {
        self.generate_report("daily")
    }
    
    fn generate_weekly_report(&self) -> Result<String, Box<dyn std::error::Error>> {
        self.generate_report("weekly")
    }
    
    fn generate_monthly_report(&self) -> Result<String, Box<dyn std::error::Error>> {
        self.generate_report("monthly")
    }
    
    fn generate_annual_report(&self) -> Result<String, Box<dyn std::error::Error>> {
        self.generate_report("annual")
    }
    
    fn generate_report(&self, period: &str) -> Result<String, Box<dyn std::error::Error>> {
        let now = Local::now();
        let start_time = match period {
            "daily" => now - chrono::Duration::days(1),
            "weekly" => now - chrono::Duration::weeks(1),
            "monthly" => now - chrono::Duration::days(30),
            "annual" => now - chrono::Duration::days(365),
            _ => now - chrono::Duration::days(1),
        };
        
        // Get threats data
        let threats = self.db.get_threats(None, 100)?;
        
        let mut threat_summary: HashMap<String, u64> = HashMap::new();
        for threat in threats {
            *threat_summary.entry(threat.threat_type).or_insert(0) += 1;
        }
        
        // Generate report content
        let mut report = format!("=== CYBERSECURITY REPORT ({}) ===\n", period.to_uppercase());
        report.push_str(&format!("Period: {} to {}\n", start_time, now));
        
        report.push_str("\nTHREAT SUMMARY:\n");
        for (threat_type, count) in threat_summary {
            report.push_str(&format!("  {}: {} occurrences\n", threat_type, count));
        }
        
        // Save to database
        self.db.connection.execute(
            "INSERT INTO reports (report_type, period, content) VALUES (?, ?, ?)",
            &["security_report", period, &report],
        )?;
        
        Ok(report)
    }
}

// Main Cybersecurity Tool
struct CyberSecurityTool {
    config: Config,
    db: Arc<DatabaseManager>,
    monitor: NetworkMonitor,
    scanner: NetworkScanner,
    traffic_gen: TrafficGenerator,
    reporter: ReportGenerator,
    command_history: Arc<Mutex<VecDeque<String>>>,
}

impl CyberSecurityTool {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let config = Config::default();
        let db = Arc::new(DatabaseManager::new(&config.database.path)?);
        
        Ok(Self {
            config: config.clone(),
            db: db.clone(),
            monitor: NetworkMonitor::new(db.clone()),
            scanner: NetworkScanner::new(db.clone()),
            traffic_gen: TrafficGenerator::new(),
            reporter: ReportGenerator::new(db.clone()),
            command_history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
        })
    }
    
    fn start(&self) {
        println!("Cybersecurity Tool Started");
        // Start background tasks here
    }
    
    fn help(&self) -> String {
        r#"
🛡️ CYBERSECURITY TOOL COMMANDS:

BASIC COMMANDS:
  help                    - Show this help message
  ping <ip>              - Ping an IP address
  exit                   - Exit the tool

MONITORING COMMANDS:
  start monitoring <ip>  - Start monitoring an IP for threats
  stop monitoring        - Stop all monitoring
  location <ip>          - Get geographical location of IP
  view threats           - View detected security threats

SCANNING COMMANDS:
  scan ip <ip>           - Scan common ports on IP
  deep scan ip <ip>      - Deep scan all ports (1-65535)

IP MANAGEMENT:
  add ip <ip> [desc]     - Add IP to monitoring list
  remove ip <ip>         - Remove IP from monitoring
  list ips               - List all monitored IPs

TRAFFIC GENERATION:
  generate traffic udp_flood <ip> <port> <duration>
  stop traffic           - Stop traffic generation

REPORTING:
  generate daily report   - Generate daily security report
  generate weekly report  - Generate weekly security report
  generate monthly report - Generate monthly security report
  generate annual report  - Generate annual security report

CURL COMMANDS:
  curl <url>             - Basic HTTP request
  curl -I <url>          - HEAD request

UTILITIES:
  history               - View command history
  clear history         - Clear command history
        "#.to_string()
    }
    
    fn ping_ip(&self, ip: &str) -> String {
        self.log_command(&format!("ping {}", ip));
        format!("Ping {}: {}", ip, if self.scanner.ping_ip(ip) { "Alive" } else { "Dead" })
    }
    
    fn start_monitoring(&self, ip: &str) -> String {
        self.log_command(&format!("start monitoring {}", ip));
        match self.monitor.start_monitoring(Some(ip)) {
            Ok(_) => format!("Started monitoring {}", ip),
            Err(e) => format!("Error starting monitoring: {}", e),
        }
    }
    
    fn stop_monitoring(&self) -> String {
        self.log_command("stop monitoring");
        self.monitor.stop_monitoring();
        "Stopped all monitoring".to_string()
    }
    
    fn get_ip_location(&self, ip: &str) -> String {
        self.log_command(&format!("location {}", ip));
        self.monitor.get_ip_location(ip)
    }
    
    fn view_threats(&self) -> String {
        self.log_command("view threats");
        match self.db.get_threats(None, 100) {
            Ok(threats) => {
                if threats.is_empty() {
                    "No threats detected".to_string()
                } else {
                    let mut result = "DETECTED THREATS:\n".to_string();
                    for threat in threats {
                        result.push_str(&format!("- {} from {} at {:?}\n", 
                            threat.threat_type, threat.ip, threat.timestamp));
                        result.push_str(&format!("  Severity: {}, Description: {}\n\n", 
                            threat.severity, threat.description));
                    }
                    result
                }
            }
            Err(e) => format!("Error retrieving threats: {}", e),
        }
    }
    
    fn scan_ports(&self, ip: &str) -> String {
        self.log_command(&format!("scan {}", ip));
        match self.scanner.scan_ports(ip, "1-1000") {
            Ok(results) => {
                if results.is_empty() {
                    format!("No open ports found on {}", ip)
                } else {
                    let mut result = format!("SCAN RESULTS for {}:\n", ip);
                    for scan in results {
                        result.push_str(&format!("Port {}: {} ({})\n", 
                            scan.port, scan.state, scan.service));
                    }
                    result
                }
            }
            Err(e) => format!("Scan error: {}", e),
        }
    }
    
    fn deep_scan(&self, ip: &str) -> String {
        self.log_command(&format!("deep scan {}", ip));
        match self.scanner.deep_scan(ip) {
            Ok(results) => {
                if results.is_empty() {
                    format!("No open ports found on {}", ip)
                } else {
                    let mut result = format!("DEEP SCAN RESULTS for {}:\n", ip);
                    for scan in results {
                        result.push_str(&format!("Port {}: {} ({})\n", 
                            scan.port, scan.state, scan.service));
                    }
                    result
                }
            }
            Err(e) => format!("Deep scan error: {}", e),
        }
    }
    
    fn add_ip(&self, ip: &str, description: &str) -> String {
        self.log_command(&format!("add ip {} {}", ip, description));
        match self.db.add_ip(ip, description) {
            Ok(_) => format!("Added IP {} to monitoring list", ip),
            Err(e) => format!("Failed to add IP {}: {}", ip, e),
        }
    }
    
    fn remove_ip(&self, ip: &str) -> String {
        self.log_command(&format!("remove ip {}", ip));
        match self.db.remove_ip(ip) {
            Ok(_) => format!("Removed IP {} from monitoring list", ip),
            Err(e) => format!("Failed to remove IP {}: {}", ip, e),
        }
    }
    
    fn list_ips(&self) -> String {
        self.log_command("list ips");
        match self.db.get_all_ips() {
            Ok(ips) => {
                if ips.is_empty() {
                    "No IPs being monitored".to_string()
                } else {
                    let mut result = "MONITORED IP ADDRESSES:\n".to_string();
                    for ip in ips {
                        result.push_str(&format!("- {}: {}\n", ip.ip, ip.description));
                    }
                    result
                }
            }
            Err(e) => format!("Error retrieving IPs: {}", e),
        }
    }
    
    fn generate_traffic(&self, traffic_type: &str, target: &str, port: u16, duration: u64) -> String {
        self.log_command(&format!("generate traffic {} {} {} {}", traffic_type, target, port, duration));
        
        match traffic_type.to_lowercase().as_str() {
            "udp_flood" => {
                match self.traffic_gen.udp_flood(target, port, duration, 1024) {
                    Ok(msg) => msg,
                    Err(e) => format!("Error generating traffic: {}", e),
                }
            }
            _ => format!("Unknown traffic type: {}", traffic_type),
        }
    }
    
    fn stop_traffic(&self) -> String {
        self.log_command("stop traffic");
        self.traffic_gen.stop_traffic()
    }
    
    fn generate_daily_report(&self) -> String {
        self.log_command("generate daily report");
        match self.reporter.generate_daily_report() {
            Ok(report) => report,
            Err(e) => format!("Error generating report: {}", e),
        }
    }
    
    fn generate_weekly_report(&self) -> String {
        self.log_command("generate weekly report");
        match self.reporter.generate_weekly_report() {
            Ok(report) => report,
            Err(e) => format!("Error generating report: {}", e),
        }
    }
    
    fn generate_monthly_report(&self) -> String {
        self.log_command("generate monthly report");
        match self.reporter.generate_monthly_report() {
            Ok(report) => report,
            Err(e) => format!("Error generating report: {}", e),
        }
    }
    
    fn generate_annual_report(&self) -> String {
        self.log_command("generate annual report");
        match self.reporter.generate_annual_report() {
            Ok(report) => report,
            Err(e) => format!("Error generating report: {}", e),
        }
    }
    
    fn view_history(&self) -> String {
        self.log_command("history");
        match self.db.get_command_history(50) {
            Ok(history) => {
                if history.is_empty() {
                    "No command history".to_string()
                } else {
                    let mut result = "COMMAND HISTORY:\n".to_string();
                    for cmd in history {
                        result.push_str(&format!("{:?}: {} - {}\n", 
                            cmd.timestamp, cmd.user, cmd.command));
                    }
                    result
                }
            }
            Err(e) => format!("Error retrieving history: {}", e),
        }
    }
    
    fn clear_history(&self) -> String {
        self.log_command("clear history");
        match self.db.connection.execute("DELETE FROM command_history", []) {
            Ok(_) => {
                self.command_history.lock().unwrap().clear();
                "Command history cleared".to_string()
            }
            Err(e) => format!("Error clearing history: {}", e),
        }
    }
    
    fn curl_simple(&self, url: &str) -> String {
        self.log_command(&format!("curl {}", url));
        match CurlCommands::curl_simple(url) {
            Ok(result) => result,
            Err(e) => format!("Curl error: {}", e),
        }
    }
    
    fn curl_head(&self, url: &str) -> String {
        self.log_command(&format!("curl -I {}", url));
        match CurlCommands::curl_head(url) {
            Ok(result) => result,
            Err(e) => format!("Curl error: {}", e),
        }
    }
    
    fn log_command(&self, command: &str) {
        self.command_history.lock().unwrap().push_back(command.to_string());
        let _ = self.db.add_command_history(command, "console");
    }
}

// Command Line Interface
struct CommandLineInterface {
    cyber_tool: CyberSecurityTool,
}

impl CommandLineInterface {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            cyber_tool: CyberSecurityTool::new()?,
        })
    }
    
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.cyber_tool.start();
        
        println!("🛡️  ACCURATE CYBER DEFENSE");
        println!("Type 'help' for available commands");
        println!("=" * 50);
        
        let stdin = io::stdin();
        
        loop {
            print!("\naccurate-cyber-defense#> ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            stdin.lock().read_line(&mut input)?;
            let input = input.trim();
            
            if input.is_empty() {
                continue;
            }
            
            if input.eq_ignore_ascii_case("exit") {
                println!("Goodbye!");
                break;
            }
            
            let response = self.process_command(input);
            println!("{}", response);
        }
        
        Ok(())
    }
    
    fn process_command(&self, command: &str) -> String {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return "".to_string();
        }
        
        let cmd = parts[0].to_lowercase();
        
        match cmd.as_str() {
            "help" => self.cyber_tool.help(),
            
            "ping" if parts.len() > 1 => self.cyber_tool.ping_ip(parts[1]),
            
            "start" if parts.len() > 2 && parts[1].eq_ignore_ascii_case("monitoring") => {
                self.cyber_tool.start_monitoring(parts[2])
            }
            
            "stop" if parts.len() > 1 && parts[1].eq_ignore_ascii_case("monitoring") => {
                self.cyber_tool.stop_monitoring()
            }
            
            "stop" if parts.len() > 1 && parts[1].eq_ignore_ascii_case("traffic") => {
                self.cyber_tool.stop_traffic()
            }
            
            "location" if parts.len() > 1 => self.cyber_tool.get_ip_location(parts[1]),
            
            "view" if parts.len() > 1 && parts[1].eq_ignore_ascii_case("threats") => {
                self.cyber_tool.view_threats()
            }
            
            "scan" if parts.len() > 2 && parts[1].eq_ignore_ascii_case("ip") => {
                self.cyber_tool.scan_ports(parts[2])
            }
            
            "deep" if parts.len() > 3 && parts[1].eq_ignore_ascii_case("scan") && parts[2].eq_ignore_ascii_case("ip") => {
                self.cyber_tool.deep_scan(parts[3])
            }
            
            "add" if parts.len() > 2 && parts[1].eq_ignore_ascii_case("ip") => {
                let description = if parts.len() > 3 { parts[3] } else { "" };
                self.cyber_tool.add_ip(parts[2], description)
            }
            
            "remove" if parts.len() > 2 && parts[1].eq_ignore_ascii_case("ip") => {
                self.cyber_tool.remove_ip(parts[2])
            }
            
            "list" if parts.len() > 1 && parts[1].eq_ignore_ascii_case("ips") => {
                self.cyber_tool.list_ips()
            }
            
            "generate" if parts.len() > 2 => {
                if parts[1].eq_ignore_ascii_case("traffic") && parts.len() > 4 {
                    let traffic_type = parts[2];
                    let target = parts[3];
                    let port = parts[4].parse().unwrap_or(80);
                    let duration = if parts.len() > 5 { parts[5].parse().unwrap_or(10) } else { 10 };
                    self.cyber_tool.generate_traffic(traffic_type, target, port, duration)
                } else if parts[1].eq_ignore_ascii_case("daily") && parts.len() > 2 && parts[2].eq_ignore_ascii_case("report") {
                    self.cyber_tool.generate_daily_report()
                } else if parts[1].eq_ignore_ascii_case("weekly") && parts.len() > 2 && parts[2].eq_ignore_ascii_case("report") {
                    self.cyber_tool.generate_weekly_report()
                } else if parts[1].eq_ignore_ascii_case("monthly") && parts.len() > 2 && parts[2].eq_ignore_ascii_case("report") {
                    self.cyber_tool.generate_monthly_report()
                } else if parts[1].eq_ignore_ascii_case("annual") && parts.len() > 2 && parts[2].eq_ignore_ascii_case("report") {
                    self.cyber_tool.generate_annual_report()
                } else {
                    "Invalid generate command. Use 'help' for usage.".to_string()
                }
            }
            
            "history" => self.cyber_tool.view_history(),
            
            "clear" if parts.len() > 1 && parts[1].eq_ignore_ascii_case("history") => {
                self.cyber_tool.clear_history()
            }
            
            "curl" if parts.len() > 1 => {
                if parts.contains(&"-I") {
                    let url = parts.last().unwrap_or(&"");
                    self.cyber_tool.curl_head(url)
                } else {
                    let url = parts.last().unwrap_or(&"");
                    self.cyber_tool.curl_simple(url)
                }
            }
            
            _ => format!("Unknown command: {}\nType 'help' for available commands.", command),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check for root privileges
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            println!("⚠️  Warning: Some features may require root privileges");
        }
    }
    
    let mut cli = CommandLineInterface::new()?;
    cli.start()?;
    
    Ok(())
}