use std::process::Command;
use regex::Regex;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;
use notify_rust::Notification;
use notify_rust::Timeout;

#[derive(Debug, Deserialize)]
struct Config {
    trigger_threshold: u64,
    recovery_threshold: u64,
    process_patterns: Vec<ProcessPattern>,
    sleep_interval_secs: u64,
}

#[derive(Debug, Deserialize)]
struct ProcessPattern {
    name: String,
    pattern: String,
    report_match: bool
}

fn get_available_memory() -> Result<u64, String> {
    let output = Command::new("free")
        .arg("-b")
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    if !output.status.success() {
        return Err("Failed to retrieve memory information".to_string());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Mem:.+ (\d+)").unwrap();

    if let Some(captures) = re.captures(output_str.as_ref()) {
        if let Some(value) = captures.get(1) {
            let memory = value.as_str().parse::<u64>().unwrap();
            return Ok(memory);
        }
    }

    Err("Failed to parse memory information".to_string())
}

fn kill_processes_until_recovery(patterns: &[ProcessPattern], recovery_threshold: u64) {
    let mut available_memory = get_available_memory().unwrap_or(0);
    let re_split = Regex::new(r"\W+").unwrap();

    while available_memory < recovery_threshold {
        for pattern in patterns {
            
            let re = Regex::new(&pattern.pattern).unwrap();

            let output = Command::new("ps")
                .arg("-eo")
                .arg("pid,rss,command")
                .output()
                .expect("Failed to execute command");

            let output_str = String::from_utf8_lossy(&output.stdout);

            let mut re_found = false;

            for line in output_str.lines().skip(1) {
                let fields: Vec<&str> = re_split.splitn(line.trim(), 3).collect();
                let (pid, rss_str, command) = (fields[0], fields[1], fields[2]);
                let rss: u64 = rss_str.parse().expect("Not a valid number");

                if re.is_match(command) {

                    re_found = true;

                    let kill_target: String = if pattern.report_match { 
                        re.captures(command)
                            .and_then(|cap| cap.get(1))
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_else(|| pattern.name.to_string())
                    } else { 
                        pattern.name.to_string()
                    };

                    println!("Killing process {}: {} holding {} MB", pid, kill_target, rss / 1024);
                    let status = Command::new("kill")
                        .arg(pid)
                        .status()
                        .expect(&format!("Failed to kill process {}: {}", pid, kill_target));
                    if status.success() {
                        Notification::new()
                            .summary("MemSen - Process Killed")
                            .body(&format!("{} ({}) process was killed to protect memory availability.", kill_target, pid))
                            .timeout(Timeout::Never)
                            .show()
                            .expect("Failed to show process-killed notification");
                        sleep(Duration::from_secs(4));
                        available_memory = get_available_memory().unwrap_or(0);
                        println!("Memory available after process killed: {} MB", available_memory / 1024 / 1024);
                    }
                }
                if available_memory > recovery_threshold {
                    println!("Freed memory above recovery threashold");
                    return;
                }
            }
            if !re_found {
                println!("Could not find process for pattern: {}", pattern.name);
            }

            available_memory = get_available_memory().unwrap_or(0);
        }
        sleep(Duration::from_secs(7));
        available_memory = get_available_memory().unwrap_or(0);
        if available_memory < recovery_threshold {
            Notification::new()
                .summary("MemSen - Free Failed!")
                .body(&format!("Target: {} MB, Current: {} MB. Unable to reduce usage below threashold.", recovery_threshold / 1024 / 1024, available_memory / 1024 / 1024))
                .timeout(Timeout::Never)
                .show()
                .expect("Failed to show process-killed notification");
        }
    }
}

fn main() {
    println!("-- Memory Sentinel --");
    let mut file = File::open("/etc/memory-sentinel/config.yaml").expect("Failed to open config file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read config file");
    let config: Config = serde_yaml::from_str(&contents).expect("Failed to parse config file");
    
    println!("Memory cleanup trigger threshold: {} MB", config.trigger_threshold / 1024 / 1024);
    println!("Available memory recovery level: {} MB", config.recovery_threshold / 1024 / 1024);

    let mut logged_memory = 0;
    loop {
        match get_available_memory() {
            Ok(memory) => {

                let diff = if memory > logged_memory {
                    memory - logged_memory
                } else {
                    logged_memory - memory
                };

                if diff > 100 * 1024 * 1024 {
                    println!("Memory available: {} MB", memory / 1024 / 1024);
                    logged_memory = memory;
                };

                if memory < config.trigger_threshold {
                    println!("Memory low! ({} MB), freeing", memory / 1024 / 1024);
                    kill_processes_until_recovery(&config.process_patterns, config.recovery_threshold);
                    println!("Stopped freeing memory");
                }
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                break;
            }
        }
        sleep(Duration::from_secs(config.sleep_interval_secs));
    }
}