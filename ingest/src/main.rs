use chrono::Utc;
use clap::Parser;
use etherparse::SlicedPacket;
use log::{error, info, warn};
use pcap::Capture;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{BaseProducer, BaseRecord, Producer};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "threat-ingest", about = "PCAP ingest service for threat detection")]
struct Args {
    /// Kafka broker address
    #[arg(long, env = "KAFKA_BROKER", default_value = "localhost:9092")]
    kafka_broker: String,

    /// Kafka topic for flow records
    #[arg(long, env = "KAFKA_TOPIC", default_value = "flow-records")]
    kafka_topic: String,

    /// Directory containing PCAP files
    #[arg(long, env = "PCAP_DIR", default_value = "./data/pcaps")]
    pcap_dir: String,

    /// Replay speed: "realtime", "2x", "10x", "max"
    #[arg(long, env = "REPLAY_SPEED", default_value = "max")]
    replay_speed: String,
}

#[derive(Serialize, Debug, Clone)]
struct PacketRecord {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    timestamp_us: i64,
    packet_len: u32,
    payload_len: usize,
    tcp_flags: Option<TcpFlags>,
    dns_query: Option<String>,
    ingest_time: String,
}

#[derive(Serialize, Debug, Clone)]
struct TcpFlags {
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
    psh: bool,
    urg: bool,
}

/// Extract DNS query name from raw UDP payload (simplified parser)
fn extract_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut offset = 12;
    let mut parts: Vec<String> = Vec::new();

    loop {
        if offset >= payload.len() {
            return None;
        }
        let len = payload[offset] as usize;
        if len == 0 {
            break;
        }
        if len > 63 || offset + 1 + len > payload.len() {
            return None;
        }
        offset += 1;
        let label = String::from_utf8_lossy(&payload[offset..offset + len]).to_string();
        parts.push(label);
        offset += len;
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

fn get_replay_delay_us(speed: &str) -> Option<f64> {
    match speed {
        "realtime" => Some(1.0),
        "2x" => Some(0.5),
        "10x" => Some(0.1),
        _ => None, // "max" = no delay
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    info!("Starting threat-ingest service");
    info!("Kafka broker: {}", args.kafka_broker);
    info!("PCAP directory: {}", args.pcap_dir);
    info!("Replay speed: {}", args.replay_speed);

    // Create Kafka producer (BaseProducer for simplicity)
    let producer: BaseProducer = ClientConfig::new()
        .set("bootstrap.servers", &args.kafka_broker)
        .set("message.timeout.ms", "10000")
        .set("queue.buffering.max.messages", "100000")
        .set("batch.num.messages", "1000")
        .set("linger.ms", "5")
        .create()
        .expect("Failed to create Kafka producer");

    info!("Kafka producer created successfully");

    let replay_delay = get_replay_delay_us(&args.replay_speed);

    // Find all PCAP files in directory
    let pcap_dir = PathBuf::from(&args.pcap_dir);
    let mut pcap_files: Vec<PathBuf> = Vec::new();

    if pcap_dir.is_dir() {
        match fs::read_dir(&pcap_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        let ext = ext.to_string_lossy().to_lowercase();
                        if ext == "pcap" || ext == "pcapng" || ext == "cap" {
                            pcap_files.push(path);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to read PCAP directory: {}", e);
                std::process::exit(1);
            }
        }
    } else if pcap_dir.is_file() {
        pcap_files.push(pcap_dir);
    }

    if pcap_files.is_empty() {
        warn!("No PCAP files found in {}. Waiting for files...", args.pcap_dir);
        loop {
            std::thread::sleep(Duration::from_secs(5));
            if let Ok(entries) = fs::read_dir(&args.pcap_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        let ext = ext.to_string_lossy().to_lowercase();
                        if ext == "pcap" || ext == "pcapng" || ext == "cap" {
                            pcap_files.push(path);
                        }
                    }
                }
                if !pcap_files.is_empty() {
                    break;
                }
            }
        }
    }

    pcap_files.sort();
    info!("Found {} PCAP file(s) to process", pcap_files.len());

    let mut total_packets: u64 = 0;
    let mut total_produced: u64 = 0;
    let start_time = std::time::Instant::now();
    let mut prev_ts_us: Option<i64> = None;

    for pcap_file in &pcap_files {
        info!("Processing: {}", pcap_file.display());

        let mut cap = match Capture::from_file(pcap_file) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to open {}: {}", pcap_file.display(), e);
                continue;
            }
        };

        while let Ok(packet) = cap.next_packet() {
            total_packets += 1;

            let ts = packet.header.ts;
            let timestamp_us = ts.tv_sec as i64 * 1_000_000 + ts.tv_usec as i64;

            // Apply replay delay if configured
            if let Some(speed_factor) = replay_delay {
                if let Some(prev) = prev_ts_us {
                    let delta_us = timestamp_us - prev;
                    if delta_us > 0 {
                        let sleep_us = (delta_us as f64 * speed_factor) as u64;
                        if sleep_us > 100 {
                            std::thread::sleep(Duration::from_micros(sleep_us));
                        }
                    }
                }
            }
            prev_ts_us = Some(timestamp_us);

            // Parse packet
            let parsed = match SlicedPacket::from_ethernet(packet.data) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Extract IP layer (using new `net` field)
            let (src_ip, dst_ip, protocol, ip_len) = match &parsed.net {
                Some(etherparse::NetSlice::Ipv4(ipv4_slice)) => {
                    let header = ipv4_slice.header();
                    (
                        format!("{}", header.source_addr()),
                        format!("{}", header.destination_addr()),
                        header.protocol().0,
                        header.total_len(),
                    )
                }
                Some(etherparse::NetSlice::Ipv6(ipv6_slice)) => {
                    let header = ipv6_slice.header();
                    (
                        format!("{}", header.source_addr()),
                        format!("{}", header.destination_addr()),
                        header.next_header().0,
                        header.payload_length() + 40,
                    )
                }
                _ => continue,
            };

            // Extract transport layer
            let (src_port, dst_port, tcp_flags) = match &parsed.transport {
                Some(etherparse::TransportSlice::Tcp(tcp)) => {
                    let flags = TcpFlags {
                        syn: tcp.syn(),
                        ack: tcp.ack(),
                        rst: tcp.rst(),
                        fin: tcp.fin(),
                        psh: tcp.psh(),
                        urg: tcp.urg(),
                    };
                    (tcp.source_port(), tcp.destination_port(), Some(flags))
                }
                Some(etherparse::TransportSlice::Udp(udp)) => {
                    (udp.source_port(), udp.destination_port(), None)
                }
                _ => (0, 0, None),
            };

            // Get payload bytes
            let payload_slice = parsed.ip_payload().map(|p| p.payload).unwrap_or(&[]);

            // Extract DNS query if port 53 UDP
            let dns_query = if protocol == 17 && (dst_port == 53 || src_port == 53) {
                extract_dns_query(payload_slice)
            } else {
                None
            };

            let record = PacketRecord {
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                src_port,
                dst_port,
                protocol,
                timestamp_us,
                packet_len: ip_len as u32,
                payload_len: payload_slice.len(),
                tcp_flags,
                dns_query,
                ingest_time: Utc::now().to_rfc3339(),
            };

            let payload_str = match serde_json::to_string(&record) {
                Ok(p) => p,
                Err(e) => {
                    error!("Serialization error: {}", e);
                    continue;
                }
            };

            let key = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);

            match producer.send(
                BaseRecord::to(&args.kafka_topic)
                    .key(&key)
                    .payload(&payload_str),
            ) {
                Ok(_) => {
                    total_produced += 1;
                }
                Err((e, _)) => {
                    error!("Failed to produce message: {}", e);
                }
            }

            // Poll to serve delivery callbacks
            producer.poll(Duration::from_millis(0));

            // Log progress every 10000 packets
            if total_packets % 10000 == 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = total_packets as f64 / elapsed;
                info!(
                    "Progress: {} packets processed, {} produced, {:.0} pkt/s",
                    total_packets, total_produced, rate
                );
            }
        }

        info!("Finished processing: {}", pcap_file.display());
    }

    // Flush remaining messages
    producer.flush(Duration::from_secs(10)).expect("Failed to flush producer");

    let elapsed = start_time.elapsed().as_secs_f64();
    let rate = total_packets as f64 / elapsed;
    info!(
        "Ingest complete: {} packets processed, {} produced in {:.2}s ({:.0} pkt/s)",
        total_packets, total_produced, elapsed, rate
    );
}
