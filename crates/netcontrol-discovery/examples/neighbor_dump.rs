fn main() {
    let all = netcontrol_discovery::neighbor::read_table(None);
    println!("all={}", all.len());
    for e in &all {
        println!("{:?} {} {:?}", e.ip, e.interface, e.mac);
    }
    let w = netcontrol_discovery::neighbor::read_table(Some("wlp2s0"));
    println!("wlp={}", w.len());
    let e = netcontrol_discovery::neighbor::read_table(Some("enp1s0f1"));
    println!("enp={}", e.len());
}
