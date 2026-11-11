use std::time::Duration;
fn main() {
    let ip = std::env::args().nth(1).and_then(|s| s.parse().ok());
    match netcontrol_discovery::mdns::discover(ip, Duration::from_secs(2)) {
        Ok(d) => {
            println!(
                "responses={} services={:?} warnings={:?}",
                d.responses, d.service_types, d.warnings
            );
            for h in d.hosts {
                println!("{:?} {:?} {:?}", h.hostname, h.addresses, h.services);
            }
        }
        Err(e) => eprintln!("error: {e}"),
    }
}
