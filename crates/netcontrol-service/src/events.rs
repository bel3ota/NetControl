use netcontrol_core::models::{
    Device, EnforcementResult, MonitoringSample, NotificationEvent, ScanReport, TrafficOverview,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    ScanStarted {
        session_id: String,
        interface: String,
        cidr: String,
        started_at: String,
    },
    ScanCompleted {
        session_id: String,
        interface: String,
        cidr: String,
        hosts_found: u32,
        new_devices: u32,
        finished_at: String,
        warnings: Vec<String>,
    },
    DeviceDiscovered {
        device: Device,
    },
    DeviceUpdated {
        device: Device,
    },
    Monitoring {
        sample: MonitoringSample,
        overview: TrafficOverview,
    },
    Enforcement {
        result: EnforcementResult,
        device: Device,
    },
    Notification {
        notification: NotificationEvent,
    },
}

impl ServerEvent {
    pub fn scan_completed(report: &ScanReport, new_devices: u32) -> Self {
        Self::ScanCompleted {
            session_id: report.session_id.clone(),
            interface: report.interface.clone(),
            cidr: report.cidr.clone(),
            hosts_found: report.hosts.len() as u32,
            new_devices,
            finished_at: report.finished_at.clone(),
            warnings: report.warnings.clone(),
        }
    }
}

pub fn notification(
    level: &str,
    title: impl Into<String>,
    message: impl Into<String>,
    device_id: Option<String>,
) -> NotificationEvent {
    NotificationEvent {
        id: uuid::Uuid::new_v4().to_string(),
        ts: netcontrol_core::util::now_ts(),
        level: level.into(),
        title: title.into(),
        message: message.into(),
        device_id,
    }
}
