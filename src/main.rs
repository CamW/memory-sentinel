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
    process_patterns: Vec<String>,
    sleep_interval_secs: u64,
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

fn kill_processes_until_recovery(regex_patterns: &[String], recovery_threshold: u64) {
    let mut available_memory = get_available_memory().unwrap_or(0);

    while available_memory < recovery_threshold {
        for pattern in regex_patterns {
            
            let mut re_found = false;
            let re = Regex::new(pattern).unwrap();

            println!("checking pattern: {}", pattern);

            let output = Command::new("ps")
                .arg("-eo")
                .arg("pid,command")
                .output()
                .expect("Failed to execute command");

            let output_str = String::from_utf8_lossy(&output.stdout);

            for line in output_str.lines().skip(1) {
                let fields: Vec<&str> = line.trim().splitn(2, ' ').collect();
                let (pid, command) = (fields[0], fields[1]);

                if re.is_match(command) {
                    println!("Killing process {} - {}", pid, command);
                    let status = Command::new("kill")
                        .arg(pid)
                        .status()
                        .expect("Failed to execute command");
                    if status.success() {
                        re_found = true;
                        Notification::new()
                            .summary("MemSen - Process Killed")
                            .body("Process was killed to protect memory availability.")
                            .timeout(Timeout::Never)
                            .image_path("./img/kill_process.png")
                            .show();
                        sleep(Duration::from_secs(2));
                    }
                }
                if available_memory > recovery_threshold {
                    println!("Freed memory above recovery threashold");
                    return;
                }
            }
            if !re_found {
                println!("Could not find / kill process - {}", pattern);
                return;
            }

            available_memory = get_available_memory().unwrap_or(0);
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

    loop {
        match get_available_memory() {
            Ok(memory) => {
                println!("Available memory: {} MB", memory / 1024 / 1024);

                if memory < config.trigger_threshold {
                    println!("Starting to free memory");
                    kill_processes_until_recovery(&config.process_patterns, config.recovery_threshold);
                    println!("Stopped memory freeing");
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