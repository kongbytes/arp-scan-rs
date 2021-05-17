use pnet::datalink::NetworkInterface;

use crate::network::TargetDetails;

pub fn is_root_user() -> bool {
    std::env::var("USER").unwrap_or(String::from("")) == String::from("root")
}

pub fn show_interfaces(interfaces: &Vec<NetworkInterface>) {

    for interface in interfaces.iter() {
        let up_text = match interface.is_up() {
            true => "UP",
            false => "DOWN"
        };
        let mac_text = match interface.mac {
            Some(mac_address) => format!("{}", mac_address),
            None => "No MAC address".to_string()
        };
        println!("{: <17} {: <7} {}", interface.name, up_text, mac_text);
    }
}

pub fn display_scan_results(mut final_result: Vec<TargetDetails>, resolve_hostname: bool) {

    final_result.sort_by_key(|item| item.ipv4);

    println!("");
    println!("| IPv4            | MAC               | Hostname              |");
    println!("|-----------------|-------------------|-----------------------|");

    for result_item in final_result {

        let hostname = match result_item.hostname {
            Some(hostname) => hostname,
            None if !resolve_hostname => String::from("(disabled)"),
            None => String::from("")
        };
        println!("| {: <15} | {: <18} | {: <21} |", result_item.ipv4, result_item.mac, hostname);
    }

    println!("");
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_detect_root_user() {

        let old_user = std::env::var("USER").unwrap();
        std::env::set_var("USER", "root");

        assert_eq!(is_root_user(), true);

        std::env::set_var("USER", old_user);
    }

    #[test]
    fn should_detect_standard_user() {

        let old_user = std::env::var("USER").unwrap();
        std::env::set_var("USER", "john");

        assert_eq!(is_root_user(), false);

        std::env::set_var("USER", old_user);
    }

}
