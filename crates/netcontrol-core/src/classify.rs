//! Device identification heuristics.
//!
//! Classification combines three independent signals: IEEE vendor, hostname
//! conventions and observed services/ports. Scores are intentionally
//! conservative — an unknown device is better than a wrong label — and every
//! result carries the reasons so the UI can explain itself.

use crate::models::DeviceCategory;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Classification {
    pub category: DeviceCategory,
    pub confidence: u8,
    pub reasons: Vec<String>,
}

impl Classification {
    fn unknown(reasons: Vec<String>) -> Self {
        Self {
            category: DeviceCategory::Unknown,
            confidence: 0,
            reasons,
        }
    }
}

pub fn classify(
    vendor: Option<&str>,
    hostname: Option<&str>,
    services: &[String],
    ports: &[u16],
) -> Classification {
    let mut scores: HashMap<DeviceCategory, u32> = HashMap::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut add = |cat: DeviceCategory, weight: u32, reason: String| {
        if !matches!(cat, DeviceCategory::Unknown) {
            *scores.entry(cat).or_insert(0) += weight;
            if reasons.len() < 12 {
                reasons.push(reason);
            }
        }
    };

    if let Some(vendor) = vendor {
        let v = vendor.to_ascii_lowercase();
        for (needles, cat) in VENDOR_RULES {
            if needles.iter().any(|n| v.contains(n)) {
                add(*cat, 3, format!("vendor matches {vendor}"));
                break;
            }
        }
    }

    if let Some(host) = hostname {
        let h = host.to_ascii_lowercase();
        for (needles, cat) in HOSTNAME_RULES {
            if needles.iter().any(|n| h.contains(n)) {
                add(*cat, 4, format!("hostname contains a {cat} pattern"));
                break;
            }
        }
    }

    for service in services {
        let s = service.to_ascii_lowercase();
        for (needles, cat) in SERVICE_RULES {
            if needles.iter().any(|n| s.contains(n)) {
                add(*cat, 4, format!("mDNS service {service}"));
                break;
            }
        }
    }

    for port in ports {
        for (ports, cat) in PORT_RULES {
            if ports.contains(port) {
                add(*cat, 3, format!("port {port} is typical of {cat}"));
                break;
            }
        }
    }

    // An Apple/Linux workstation that exposes SSH and SMB is a computer even
    // if the manufacturer is ambiguous.
    if ports.contains(&445) || ports.contains(&3389) || ports.contains(&5900) {
        add(
            DeviceCategory::Desktop,
            1,
            "desktop file-sharing port".into(),
        );
    }

    let mut ranked: Vec<(DeviceCategory, u32)> = scores.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.as_str().cmp(b.0.as_str())));
    match ranked.first() {
        Some((cat, score)) if *score >= 3 => {
            let ambiguous = ranked
                .get(1)
                .map(|(_, second)| *second + 2 >= *score)
                .unwrap_or(false);
            if ambiguous {
                reasons.push("signals were ambiguous; keeping the leading category".into());
            }
            Classification {
                category: *cat,
                confidence: (*score).min(999).min(100) as u8,
                reasons,
            }
        }
        _ => Classification::unknown(reasons),
    }
}

/// Merged classification that respects the OUI lookup and mDNS data.
pub fn classify_device(
    mac: Option<&str>,
    hostname: Option<&str>,
    services: &[String],
    ports: &[u16],
) -> Classification {
    let vendor = mac.and_then(crate::oui::lookup);
    classify(vendor.as_deref(), hostname, services, ports)
}

const VENDOR_RULES: &[(&[&str], DeviceCategory)] = &[
    (
        &[
            "canon",
            "epson",
            "brother",
            "xerox",
            "ricoh",
            "kyocera",
            "lexmark",
            "zebra technologies",
        ],
        DeviceCategory::Printer,
    ),
    (
        &["sonos", "bose", "harman", "bang & olufsen"],
        DeviceCategory::Speaker,
    ),
    (
        &["roku", "vizio", "hisense", "tcl ", "humax", "arris"],
        DeviceCategory::Streaming,
    ),
    (
        &[
            "sony interactive",
            "sony computer",
            "nintendo",
            "microsoft xbox",
        ],
        DeviceCategory::GameConsole,
    ),
    (
        &[
            "hikvision",
            "dahua",
            "reolink",
            "amcrest",
            "axis communications",
            "hanwha",
            "uniview",
        ],
        DeviceCategory::Camera,
    ),
    (
        &["synology", "qnap", "western digital", "drobo", "buffalo"],
        DeviceCategory::Nas,
    ),
    (
        &[
            "ubiquiti",
            "mikrotik",
            "tp-link",
            "netgear",
            "d-link",
            "zyxel",
            "aruba",
            "juniper",
            "cisco systems",
            "meraki",
            "ruckus",
            "sagemcom",
            "technicolor",
            "calix",
            "actiontec",
            "avm gmbh",
        ],
        DeviceCategory::Router,
    ),
    (
        &[
            "espressif",
            "tuya",
            "shelly",
            "sonoff",
            "signify",
            "lifx",
            "particle industries",
            "arduino",
            "raspberry pi",
            "itead",
            "nordic semiconductor",
        ],
        DeviceCategory::Iot,
    ),
    (
        &["garmin", "fitbit", "withings", "polar electro"],
        DeviceCategory::Wearable,
    ),
    (
        &["supermicro", "tyan", "quanta computer"],
        DeviceCategory::Server,
    ),
    (
        &[
            "dell",
            "lenovo",
            "lcfc",
            "acer",
            "asustek",
            "micro-star",
            "gigabyte",
            "toshiba",
            "fujitsu",
            "razer",
            "framework",
        ],
        DeviceCategory::Laptop,
    ),
    (
        &["intel corporate", "realtek", "via technologies"],
        DeviceCategory::Desktop,
    ),
    (
        &[
            "samsung electronics",
            "xiaomi",
            "huawei",
            "oneplus",
            "oppo",
            "vivo",
            "motorola mobility",
            "nokia",
            "zte",
            "honor",
            "tcl communication",
            "fairphone",
        ],
        DeviceCategory::Smartphone,
    ),
    (&["apple"], DeviceCategory::Unknown),
    (&["google"], DeviceCategory::Streaming),
    (
        &["amazon technologies", "amazon.com"],
        DeviceCategory::Streaming,
    ),
    (
        &[
            "lg electronics",
            "philips",
            "sharp corporation",
            "panasonic",
        ],
        DeviceCategory::SmartTv,
    ),
];

const HOSTNAME_RULES: &[(&[&str], DeviceCategory)] = &[
    (
        &[
            "iphone", "android-", "pixel-", "galaxy-", "oneplus", "redmi", "poco",
        ],
        DeviceCategory::Smartphone,
    ),
    (&["ipad", "tab-", "tablet"], DeviceCategory::Tablet),
    (
        &[
            "macbook",
            "laptop",
            "notebook",
            "thinkpad",
            "ideapad",
            "xps-",
            "surface-laptop",
        ],
        DeviceCategory::Laptop,
    ),
    (
        &[
            "imac",
            "desktop",
            "workstation",
            "pc-",
            "msi-",
            "precision-",
        ],
        DeviceCategory::Desktop,
    ),
    (
        &[
            "printer",
            "print-",
            "epson",
            "brother",
            "canon-",
            "mfc-",
            "laserjet",
            "officejet",
            "deskjet",
        ],
        DeviceCategory::Printer,
    ),
    (
        &[
            "tv",
            "bravia",
            "webos",
            "tizen",
            "roku",
            "firetv",
            "chromecast",
            "appletv",
            "shield",
        ],
        DeviceCategory::SmartTv,
    ),
    (
        &[
            "router", "gateway", "openwrt", "routeros", "fritz", "unifi", "deco", "orbi", "archer",
        ],
        DeviceCategory::Router,
    ),
    (&["switch", "usw-", "gs-", "tl-sg"], DeviceCategory::Switch),
    (
        &["ap-", "access-point", "uap-", "wifi-ap"],
        DeviceCategory::AccessPoint,
    ),
    (
        &["camera", "ipcam", "cam-", "doorbell", "nvr", "dvr"],
        DeviceCategory::Camera,
    ),
    (
        &["echo", "homepod", "sonos", "speaker", "soundbar"],
        DeviceCategory::Speaker,
    ),
    (
        &["playstation", "xbox", "switch-"],
        DeviceCategory::GameConsole,
    ),
    (
        &["nas", "diskstation", "readynas", "truenas", "freenas"],
        DeviceCategory::Nas,
    ),
    (
        &[
            "server",
            "proxmox",
            "esxi",
            "ubuntu-server",
            "debian",
            "docker",
        ],
        DeviceCategory::Server,
    ),
    (
        &["watch", "band", "fitbit", "garmin"],
        DeviceCategory::Wearable,
    ),
    (
        &[
            "esp32", "esp8266", "shelly", "tasmota", "tuya", "homekit", "sensor",
        ],
        DeviceCategory::Iot,
    ),
    (&["raspberrypi", "rpi-"], DeviceCategory::Iot),
];

const SERVICE_RULES: &[(&[&str], DeviceCategory)] = &[
    (
        &["_ipp", "_printer", "_pdl-datastream", "_scanner"],
        DeviceCategory::Printer,
    ),
    (
        &[
            "_airplay",
            "_raop",
            "_googlecast",
            "_spotify-connect",
            "_sonos",
            "_screenbeam",
        ],
        DeviceCategory::Streaming,
    ),
    (
        &[
            "_smb",
            "_afpovertcp",
            "_workstation",
            "_rfb",
            "_device-info",
        ],
        DeviceCategory::Desktop,
    ),
    (&["_ssh", "_sftp-ssh"], DeviceCategory::Server),
    (
        &[
            "_homekit",
            "_hap",
            "_matter",
            "_tuya",
            "_esphomelib",
            "_shelly",
        ],
        DeviceCategory::Iot,
    ),
    (
        &["_http", "_https", "_axis-video", "_rtsp", "_onvif"],
        DeviceCategory::Camera,
    ),
    (&["_ipp-usb", "_uscan"], DeviceCategory::Printer),
    (
        &["_companion-link", "_apple-mobdev", "_airdrop"],
        DeviceCategory::Smartphone,
    ),
    (&["_xbox", "_playstation"], DeviceCategory::GameConsole),
];

const PORT_RULES: &[(&[u16], DeviceCategory)] = &[
    (&[631, 515, 9100, 427], DeviceCategory::Printer),
    (&[32400, 8009, 7000, 9080], DeviceCategory::Streaming),
    (&[554, 8554, 8000, 37777], DeviceCategory::Camera),
    (&[1883, 8883, 5683], DeviceCategory::Iot),
    (&[445, 3389, 5900, 548], DeviceCategory::Desktop),
    (&[22, 111, 2049, 3260], DeviceCategory::Server),
    (&[62078], DeviceCategory::Smartphone),
    (&[53, 67, 68, 1900], DeviceCategory::Router),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printer_by_vendor_and_services() {
        let c = classify(Some("Canon Inc."), Some("office-printer"), &[], &[]);
        assert_eq!(c.category, DeviceCategory::Printer);
        let c = classify(None, None, &["_ipp._tcp.local".into()], &[631]);
        assert_eq!(c.category, DeviceCategory::Printer);
    }

    #[test]
    fn phone_hostname() {
        let c = classify(Some("Samsung Electronics"), Some("galaxy-s24"), &[], &[]);
        assert_eq!(c.category, DeviceCategory::Smartphone);
    }

    #[test]
    fn unknown_is_not_guessed() {
        let c = classify(Some("Apple, Inc."), Some("unknown-host"), &[], &[]);
        assert_eq!(c.category, DeviceCategory::Unknown);
        let c = classify(None, None, &[], &[]);
        assert_eq!(c.category, DeviceCategory::Unknown);
    }

    #[test]
    fn tv_vendor() {
        let c = classify(Some("Roku, Inc."), None, &[], &[]);
        assert_eq!(c.category, DeviceCategory::Streaming);
    }
}
