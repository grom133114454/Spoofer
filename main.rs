use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

extern crate chrono;
extern crate rand;
extern crate winreg;

use chrono::Local;
use rand::Rng;
use winreg::{
    enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS},
    RegKey,
};

fn get_windows_version() -> String {
    let output = Command::new("cmd")
        .args(&["/c", "ver"])
        .output()
        .unwrap_or_else(|_| {
            Command::new("powershell")
                .args(&[
                    "-Command",
                    "(Get-CimInstance -ClassName Win32_OperatingSystem).Version",
                ])
                .output()
                .unwrap_or_else(|_| std::process::Output {
                    status: std::process::ExitStatus::default(),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
        });
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn log_message(message: &str) -> io::Result<()> {
    let mut log_file_path = PathBuf::new();
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            log_file_path.push(parent);
            log_file_path.push("spoofer_log.txt");
        } else {
            log_file_path.push("spoofer_log.txt");
        }
    } else {
        log_file_path.push("spoofer_log.txt");
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(&log_file_path)?;
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    writeln!(file, "[{}] {}", timestamp, message)?;
    println!("[{}] {}", timestamp, message);
    Ok(())
}

fn generate_random_hwid() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "0123456789ABCDEF".chars().collect();
    let segments = vec![8, 4, 4, 4, 12];
    let mut hwid = String::new();
    for (i, &len) in segments.iter().enumerate() {
        for _ in 0..len {
            hwid.push(chars[rng.gen_range(0..chars.len())]);
        }
        if i < segments.len() - 1 {
            hwid.push('-');
        }
    }
    hwid
}

fn has_admin_privileges() -> bool {
    let output = Command::new("net").args(&["session"]).output();

    match output {
        Ok(o) => {
            let success = o.status.success();
            log_message(&format!(
                "Admin check: net session output success: {}",
                success
            ))
            .unwrap_or_default();
            if !o.stderr.is_empty() {
                log_message(&format!(
                    "Admin check: net session stderr: {}",
                    String::from_utf8_lossy(&o.stderr)
                ))
                .unwrap_or_default();
            }
            success
        }
        Err(e) => {
            log_message(&format!("Admin check: Error running net session: {}", e))
                .unwrap_or_default();
            false
        }
    }
}

fn spoof_system_hwid() -> io::Result<()> {
    log_message("Starting system HWID spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let paths = [
        (
            "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            vec!["ComputerHardwareId", "SystemProductName"],
        ),
        (
            "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
            vec!["Identifier"],
        ),
        ("SOFTWARE\\Microsoft\\Cryptography", vec!["MachineGuid"]),
        (
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            vec!["ProductId"],
        ),
    ];

    for (path, keys) in paths.iter() {
        match hklm.open_subkey_with_flags(path, KEY_ALL_ACCESS) {
            Ok(subkey) => {
                for key in keys {
                    let new_hwid = generate_random_hwid();
                    subkey.set_value(key, &new_hwid)?;
                    log_message(&format!("Spoofed {} in {}: {}", key, path, new_hwid))?;
                }
                return Ok(());
            }
            Err(e) => log_message(&format!("Error accessing {}: {}", path, e))?,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Failed to spoof system HWID",
    ))
}

fn spoof_disk_serial() -> io::Result<()> {
    log_message("Starting disk serial spoofing...")?;
    let new_serial = generate_random_hwid();
    let diskpart_script = format!("select disk 0\nuniqueid disk id={}\nexit\n", new_serial);

    let script_path = "diskpart_script.txt";
    fs::write(script_path, &diskpart_script)?;

    let output = Command::new("diskpart")
        .arg("/s")
        .arg(script_path)
        .output()?;
    if output.status.success() {
        log_message(&format!("Disk serial spoofed: {}", new_serial))?;
        let _ = fs::remove_file(script_path);
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        log_message(&format!("Diskpart error: {}", error))?;
        let _ = fs::remove_file(script_path);
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to spoof disk serial",
        ))
    }
}

fn spoof_mac_address() -> io::Result<()> {
    log_message("Starting MAC address spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let adapters_path =
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0012";

    match hklm.open_subkey_with_flags(adapters_path, KEY_ALL_ACCESS) {
        Ok(adapter_key) => {
            let new_mac: String = (0..6)
                .map(|_| format!("{:02X}", rand::thread_rng().gen_range(0..256)))
                .collect::<Vec<String>>()
                .join("");
            adapter_key.set_value("NetworkAddress", &new_mac)?;
            log_message(&format!(
                "MAC spoofed for adapter {}: {}",
                adapters_path, new_mac
            ))?;

            let powershell_command_disable =
                format!("Disable-NetAdapter -Name \"Ethernet\" -Confirm:$false");
            log_message(&format!(
                "Executing PowerShell command: {}",
                powershell_command_disable
            ))?;
            Command::new("powershell")
                .args(&["-Command", &powershell_command_disable])
                .output()?;
            thread::sleep(Duration::from_secs(2));

            let powershell_command_enable =
                format!("Enable-NetAdapter -Name \"Ethernet\" -Confirm:$false"); // Assuming 'Ethernet' is a common adapter name
            log_message(&format!(
                "Executing PowerShell command: {}",
                powershell_command_enable
            ))?;
            Command::new("powershell")
                .args(&["-Command", &powershell_command_enable])
                .output()?;

            Ok(())
        }
        Err(e) => {
            log_message(&format!("Error accessing adapter {}: {}", adapters_path, e))?;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to access specified network adapter",
            ))
        }
    }
}

fn spoof_computer_name() -> io::Result<()> {
    log_message("Starting Computer Name spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";

    match hklm.open_subkey_with_flags(path, KEY_ALL_ACCESS) {
        Ok(subkey) => {
            let new_name = format!("S-{}", generate_random_string(15));
            subkey.set_value("ComputerName", &new_name)?;
            log_message(&format!("Computer Name spoofed: {}", new_name))?;
            Ok(())
        }
        Err(e) => {
            log_message(&format!("Error accessing ComputerName registry: {}", e))?;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to access ComputerName registry",
            ))
        }
    }
}

fn generate_random_string(len: usize) -> String {
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

fn spoof_product_id() -> io::Result<()> {
    log_message("Starting Product ID spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    match hklm.open_subkey_with_flags(path, KEY_ALL_ACCESS) {
        Ok(subkey) => {
            let new_product_id = format!(
                "{}-{}-{}-{}",
                generate_random_string(5),
                generate_random_string(5),
                generate_random_string(5),
                generate_random_string(5)
            );
            subkey.set_value("ProductID", &new_product_id)?;
            log_message(&format!("Product ID spoofed: {}", new_product_id))?;
            Ok(())
        }
        Err(e) => {
            log_message(&format!("Error accessing ProductID registry: {}", e))?;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to access ProductID registry",
            ))
        }
    }
}

fn spoof_machine_guid() -> io::Result<()> {
    log_message("Starting MachineGuid spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = "SOFTWARE\\Microsoft\\Cryptography";

    match hklm.open_subkey_with_flags(path, KEY_ALL_ACCESS) {
        Ok(subkey) => {
            let new_guid = generate_random_hwid();
            subkey.set_value("MachineGuid", &new_guid)?;
            log_message(&format!("MachineGuid spoofed: {}", new_guid))?;
            Ok(())
        }
        Err(e) => {
            log_message(&format!("Error accessing MachineGuid registry: {}", e))?;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to access MachineGuid registry",
            ))
        }
    }
}

fn spoof_volume_id() -> io::Result<()> {
    log_message("Starting Volume ID spoofing...")?;
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            "Get-Volume | ForEach-Object { $driveLetter = $_.DriveLetter; if ($driveLetter) { $newVolumeId = (Get-Random -Minimum 0 -Maximum 4294967295).ToString(\"X8\"); fsutil volume dismount $driveLetter`:` | Out-Null; fsutil volume setid $driveLetter`:` $newVolumeId | Out-Null; Write-Host \"Volume ID for drive $driveLetter spoofed to $newVolumeId\" } }"
        ])
        .output()?;

    if output.status.success() {
        log_message(&format!("Volume IDs spoofed successfully."))?;
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        log_message(&format!("Failed to spoof Volume IDs: {}", error))?;
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to spoof Volume IDs",
        ))
    }
}

fn spoof_bios_uuid() -> io::Result<()> {
    log_message("Starting BIOS UUID spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let bios_path = "HARDWARE\\DESCRIPTION\\System";

    match hklm.open_subkey_with_flags(bios_path, KEY_ALL_ACCESS) {
        Ok(bios_key) => {
            let new_uuid = generate_random_hwid();
            bios_key.set_value("SystemBiosVersion", &format!("CustomBIOS-{}", new_uuid))?;
            bios_key.set_value("SystemBiosDate", &"01/01/2023")?;
            log_message(&format!("BIOS UUID spoofed: {}", new_uuid))?;
            Ok(())
        }
        Err(e) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Failed to access {}: {}", bios_path, e),
        )),
    }
}

fn spoof_tpm_info() -> io::Result<()> {
    log_message("Starting TPM information spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let tpm_path = "SYSTEM\\CurrentControlSet\\Services\\TPM";

    match hklm.open_subkey_with_flags(tpm_path, KEY_ALL_ACCESS) {
        Ok(tpm_key) => {
            let new_id = generate_random_hwid();
            tpm_key.set_value("TPM_ID", &new_id)?;
            log_message(&format!("TPM ID spoofed: {}", new_id))?;
            Ok(())
        }
        Err(e) => {
            log_message(&format!("Error accessing TPM: {}", e))?;
            Ok(())
        }
    }
}

fn spoof_smbios() -> io::Result<()> {
    log_message("Starting SMBIOS information spoofing...")?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let smbios_path = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation";

    match hklm.open_subkey_with_flags(smbios_path, KEY_ALL_ACCESS) {
        Ok(smbios_key) => {
            let values = [
                "BaseBoardManufacturer",
                "BaseBoardProduct",
                "BaseBoardVersion",
                "BiosVersion",
                "SystemManufacturer",
                "SystemProductName",
                "SystemVersion",
            ];

            for value in values.iter() {
                let new_value = format!("CUSTOM_{}", generate_random_hwid());
                smbios_key.set_value(value, &new_value)?;
                log_message(&format!("SMBIOS {} spoofed: {}", value, new_value))?;
            }
            Ok(())
        }
        Err(e) => {
            log_message(&format!("Error accessing SMBIOS: {}", e))?;
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to spoof SMBIOS",
            ))
        }
    }
}

fn auto_spoof() -> io::Result<()> {
    log_message(&format!(
        "Starting HWID spoofer for Windows {}. Spoofing all components...",
        get_windows_version()
    ))?;

    elevate_privileges()?;

    let operations: [(&str, fn() -> io::Result<()>); 10] = [
        ("system HWID", spoof_system_hwid),
        ("disk serial", spoof_disk_serial),
        ("MAC addresses", spoof_mac_address),
        ("Computer Name", spoof_computer_name),
        ("Product ID", spoof_product_id),
        ("MachineGuid", spoof_machine_guid),
        ("BIOS UUID", spoof_bios_uuid),
        ("Volume ID", spoof_volume_id),
        ("TPM info", spoof_tpm_info),
        ("SMBIOS", spoof_smbios),
    ];

    for (name, func) in operations.iter() {
        match func() {
            Ok(_) => log_message(&format!("Spoofing {} completed successfully", name))?,
            Err(e) => log_message(&format!("Failed to spoof {}: {}", name, e))?,
        }

        thread::sleep(Duration::from_secs(1));
    }

    log_message("All spoofing operations completed successfully.")?;
    Ok(())
}

fn elevate_privileges() -> io::Result<()> {
    if !has_admin_privileges() {
        log_message("Administrator privileges required. Requesting elevation...")?;
        let exe_path = std::env::current_exe()?.to_string_lossy().to_string();
        let cwd = std::env::current_dir()?.to_string_lossy().to_string();
        let mut cmd = Command::new("powershell")
            .args(&[
                "-Command",
                "Start-Process",
                &format!("'{}'", exe_path),
                "-WorkingDirectory",
                &format!("'{}'", cwd),
                "-Verb",
                "RunAs",
            ])
            .spawn()?;
        let status = cmd.wait()?;
        if !status.success() {
            log_message("Failed to obtain administrator privileges")?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Administrator privileges required",
            ));
        }

        std::process::exit(0);
    }
    Ok(())
}

fn main() -> io::Result<()> {
    log_message("Program started.")?;
    match auto_spoof() {
        Ok(_) => log_message("Automatic spoofing completed successfully,restart you Pc.")?,
        Err(e) => log_message(&format!("Critical spoofing error: {}", e))?,
    }

    log_message("Press Enter to exit...")?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;

    Ok(())
}
