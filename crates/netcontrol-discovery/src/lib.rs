//! NetControl discovery engine.
//!
//! Real, privilege-aware LAN discovery: interface detection, neighbor/ARP
//! cache priming, unprivileged ICMP, TCP probing, optional Nmap, mDNS and
//! reverse DNS. All results are plain `HostObservation`s consumed by the
//! persistence layer and every UI.

pub mod icmp;
pub mod interfaces;
pub mod mdns;
pub mod neighbor;
pub mod nmap;
pub mod scanner;

pub use interfaces::{InterfaceManager, ToolAvailability};
pub use scanner::DiscoveryEngine;

pub use netcontrol_core as core;
