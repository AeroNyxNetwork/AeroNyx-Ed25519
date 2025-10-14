// src/remote_command_handler/handlers/system_ops.rs
// ============================================
// System information handlers
// ============================================

use tracing::warn;
use crate::remote_command_handler::{
    RemoteCommandData, RemoteCommandError, RemoteCommandHandler,
};

/// Handle system info request
pub async fn handle_system_info(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let categories = command.categories.unwrap_or_else(|| {
        vec!["cpu".to_string(), "memory".to_string(), "disk".to_string()]
    });

    let mut result = serde_json::json!({});
    let mut errors = Vec::new();

    for category in categories {
        match category.as_str() {
            "cpu" => {
                match get_cpu_info(handler).await {
                    Ok(info) => result["cpu"] = info,
                    Err(e) => {
                        errors.push(format!("cpu: {}", e.message));
                        result["cpu"] = serde_json::json!({ "error": e.message });
                    }
                }
            }
            "memory" => {
                match get_memory_info(handler).await {
                    Ok(info) => result["memory"] = info,
                    Err(e) => {
                        errors.push(format!("memory: {}", e.message));
                        result["memory"] = serde_json::json!({ "error": e.message });
                    }
                }
            }
            "disk" => {
                match get_disk_info(handler).await {
                    Ok(info) => result["disk"] = info,
                    Err(e) => {
                        errors.push(format!("disk: {}", e.message));
                        result["disk"] = serde_json::json!({ "error": e.message });
                    }
                }
            }
            "network" => {
                match get_network_info(handler).await {
                    Ok(info) => result["network"] = info,
                    Err(e) => {
                        errors.push(format!("network: {}", e.message));
                        result["network"] = serde_json::json!({ "error": e.message });
                    }
                }
            }
            "process" => {
                match get_process_info(handler).await {
                    Ok(info) => result["process"] = info,
                    Err(e) => {
                        errors.push(format!("process: {}", e.message));
                        result["process"] = serde_json::json!({ "error": e.message });
                    }
                }
            }
            _ => {
                warn!("Unknown system info category: {}", category);
            }
        }
    }

    if !errors.is_empty() {
        result["warnings"] = serde_json::json!(errors);
    }

    Ok(result)
}

/// Get CPU information
async fn get_cpu_info(
    handler: &RemoteCommandHandler,
) -> Result<serde_json::Value, RemoteCommandError> {
    let load = sys_info::loadavg().map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get load average: {}", e), None)
    })?;

    let cpu_num = sys_info::cpu_num().unwrap_or(1) as u64;
    let cpu_speed = sys_info::cpu_speed().unwrap_or(0) as u64;

    let usage_percent = (load.one / cpu_num as f64 * 100.0).min(100.0);

    Ok(serde_json::json!({
        "usage_percent": usage_percent,
        "load_average": [load.one, load.five, load.fifteen],
        "cores": cpu_num,
        "speed_mhz": cpu_speed,
    }))
}

/// Get memory information
async fn get_memory_info(
    handler: &RemoteCommandHandler,
) -> Result<serde_json::Value, RemoteCommandError> {
    let mem = sys_info::mem_info().map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get memory info: {}", e), None)
    })?;

    Ok(serde_json::json!({
        "total": mem.total * 1024,
        "used": (mem.total - mem.avail) * 1024,
        "free": mem.avail * 1024,
        "percent": ((mem.total - mem.avail) as f64 / mem.total as f64 * 100.0),
    }))
}

/// Get disk information
async fn get_disk_info(
    handler: &RemoteCommandHandler,
) -> Result<serde_json::Value, RemoteCommandError> {
    let disk = sys_info::disk_info().map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get disk info: {}", e), None)
    })?;

    Ok(serde_json::json!({
        "total": disk.total * 1024,
        "used": (disk.total - disk.free) * 1024,
        "free": disk.free * 1024,
        "percent": ((disk.total - disk.free) as f64 / disk.total as f64 * 100.0),
    }))
}

/// Get network information
async fn get_network_info(
    _handler: &RemoteCommandHandler,
) -> Result<serde_json::Value, RemoteCommandError> {
    use pnet::datalink;

    let mut interfaces = serde_json::json!({});

    for interface in datalink::interfaces() {
        if interface.is_loopback() {
            continue;
        }

        let mut if_info = serde_json::json!({});

        for ip in &interface.ips {
            if let Some(ip_addr) = ip.ip().to_string().split('/').next() {
                if_info["ip"] = serde_json::json!(ip_addr);
                break;
            }
        }

        if_info["rx_bytes"] = serde_json::json!(0);
        if_info["tx_bytes"] = serde_json::json!(0);

        interfaces[interface.name.clone()] = if_info;
    }

    Ok(serde_json::json!({
        "interfaces": interfaces,
    }))
}

/// Get process information
async fn get_process_info(
    _handler: &RemoteCommandHandler,
) -> Result<serde_json::Value, RemoteCommandError> {
    let pid = std::process::id();
    
    let mem_info = sys_info::mem_info().unwrap_or(sys_info::MemInfo {
        total: 0,
        free: 0,
        avail: 0,
        buffers: 0,
        cached: 0,
        swap_total: 0,
        swap_free: 0,
    });
    let memory_mb = (mem_info.total - mem_info.avail) / 1024;

    Ok(serde_json::json!({
        "pid": pid,
        "uptime_seconds": 0,
        "cpu_percent": 0.0,
        "memory_mb": memory_mb,
    }))
}
