use clap::Parser;
use rand::Rng;
use std::net::IpAddr;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "syslog-traffic-generator",
    version = "0.1.0",
    about = "syslog traffic generator for high volume experiments"
)]
struct Args {
    #[arg(
        short = 'd',
        long = "destination",
        value_name = "destination IP",
        default_value = "127.0.0.1"
    )]
    target_ip: IpAddr,
    #[arg(
        short = 'p',
        long = "port",
        value_name = "destination UDP port",
        default_value_t = 514
    )]
    target_port: u16,
    #[arg(
        short = 't',
        long = "threads",
        value_name = "number of tx threads",
        default_value_t = 1
    )]
    threads_nr: usize,
    #[arg(
        short = 's',
        long = "sleep-us",
        value_name = "microseconds to sleep between each packet",
        default_value_t = 1
    )]
    sleep_us: u64,
    #[arg(
        short = 'P',
        long = "priority-max",
        value_name = "max priority in a message",
        default_value_t = 191
    )]
    priority_max: u8,
    #[arg(
        short = 'W',
        long = "words-max",
        value_name = "max number of words in a message",
        default_value_t = 20
    )]
    words_max: u8,
    #[arg(
        short = 'F',
        long = "words-fixed",
        value_name = "fixed number of words in a message (bitrate will not fluctuate)",
        default_value_t = 0
    )]
    words_fixed: u8,
    #[arg(
        short = 'c',
        long = "corrupt",
        value_name = "number of bytes to be corrupted (changed to 0..=255 randomly)",
        default_value_t = 0
    )]
    corrupt: u8,
}

#[derive(Debug)]
struct Target {
    ip: IpAddr,
    port: u16,
}

impl Target {
    fn is_ipv4(&self) -> bool {
        self.ip.is_ipv4()
    }

    fn as_str(&self) -> String {
        if self.is_ipv4() {
            format!("{}:{}", self.ip, self.port)
        } else {
            format!("[{}]:{}", self.ip, self.port)
        }
    }

    fn bind_to(&self) -> String {
        if self.is_ipv4() {
            String::from("0.0.0.0:0")
        } else {
            String::from("[::1]:0")
        }
    }
}

#[derive(Debug)]
struct Options {
    sleep_us: u64,
    priority_max: u8,
    words_max: u8,
    words_fixed: u8,
    corrupt: u8,
}

#[derive(Debug)]
struct Stats {
    packets: u64,
    bytes: u64,
}

struct Config {
    target: Target,
    options: Options,
}

fn tx_thread(signalled: Arc<AtomicBool>, config: Arc<Config>, stats: Arc<Mutex<Stats>>) {
    let socket = UdpSocket::bind(config.target.bind_to()).unwrap();

    let mut rng = rand::thread_rng();

    let mut messages = vec![];

    for _ in 0..(4 * 1024) {
        let length = if config.options.words_fixed != 0 {
            config.options.words_fixed
        } else {
            rng.gen_range(1..=config.options.words_max)
        };

        let words = rand_word::new(length as usize);
        let prio = rng.gen_range(0..=config.options.priority_max);
        let message = format!("<{prio}> {words}");

        messages.push(message);
    }

    let mut tstats = Stats {
        packets: 0,
        bytes: 0,
    };

    let mut tick = Instant::now();

    loop {
        let idx = rng.gen_range(0..messages.len());
        let mut buf: Vec<u8>;

        if config.options.corrupt != 0 {
            buf = messages[idx].clone().into_bytes();

            for _ in 0..std::cmp::min(config.options.corrupt as usize, buf.len()) {
                let idx = rng.gen_range(0..buf.len());

                buf[idx] = rng.gen_range(0..=255);
            }
        } else {
            buf = messages[idx].as_bytes().to_vec();
        }

        let bytes = socket.send_to(&buf, config.target.as_str()).unwrap();

        tstats.packets += 1;
        tstats.bytes += bytes as u64;

        thread::sleep(Duration::from_micros(config.options.sleep_us));

        if tick.elapsed() >= Duration::from_millis(100) {
            tick = Instant::now();

            let mut stats = stats.lock().unwrap();

            stats.packets += tstats.packets;
            stats.bytes += tstats.bytes;

            tstats.packets = 0;
            tstats.bytes = 0;
        }

        if signalled.load(Ordering::SeqCst) {
            break;
        }
    }
}

fn main() {
    let args = Args::parse();

    println!("{:?}", args);

    if args.threads_nr == 0 {
        eprintln!("at least one tx thread is needed");
        std::process::exit(1);
    }

    let config = Config {
        target: Target {
            ip: args.target_ip,
            port: args.target_port,
        },
        options: Options {
            sleep_us: args.sleep_us,
            priority_max: args.priority_max,
            words_max: args.words_max,
            words_fixed: args.words_fixed,
            corrupt: args.corrupt,
        },
    };

    let stats = Stats {
        packets: 0,
        bytes: 0,
    };

    let signalled = Arc::new(AtomicBool::new(false));
    let sig = Arc::clone(&signalled);

    ctrlc::set_handler(move || {
        sig.store(true, Ordering::SeqCst);
    })
    .expect("ctrl+c setup error");

    let config = Arc::new(config);
    let stats = Arc::new(Mutex::new(stats));

    let mut handles = vec![];

    for _ in 0..args.threads_nr {
        let signalled = Arc::clone(&signalled);
        let config = Arc::clone(&config);
        let stats = Arc::clone(&stats);

        let handle = thread::spawn(move || {
            tx_thread(signalled, config, stats);
        });

        handles.push(handle);
    }

    loop {
        thread::sleep(Duration::from_secs(1));

        {
            let mut stats = stats.lock().unwrap();

            println!(
                "{:.1} k pps, {:.1} Mbit/s -> {}",
                stats.packets as f64 / 1000_f64,
                (stats.bytes * 8) as f64 / (1024 * 1024) as f64,
                config.target.as_str(),
            );

            stats.packets = 0;
            stats.bytes = 0;
        }

        if signalled.load(Ordering::SeqCst) {
            break;
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
