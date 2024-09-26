use crate::error::OPGError;

#[derive(Default)]
pub struct Firewall {}

impl Firewall {
    pub fn new() -> Self {
        Firewall::default()
    }

    pub fn start(&self) -> Result<(), OPGError> {
        let ipt = iptables::new(false)?;
        // Flush existing rules
        ipt.flush_chain("filter", "INPUT")?;
        ipt.flush_chain("filter", "FORWARD")?;
        ipt.flush_chain("filter", "OUTPUT")?;

        // Set default policies to drop incoming and forwarded packets
        ipt.append("filter", "INPUT", "-j DROP")?;
        ipt.append("filter", "FORWARD", "-j DROP")?;
        ipt.append("filter", "OUTPUT", "-j ACCEPT")?;

        // Allow loopback interface traffic
        ipt.append("filter", "INPUT", "-i lo -j ACCEPT")?;

        // Allow established and related connections
        ipt.append(
            "filter",
            "INPUT",
            "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        )?;

        // Allow SSH connections on port 22
        ipt.append("filter", "INPUT", "-p tcp --dport 22 -j ACCEPT")?;

        // Log and drop everything else
        ipt.append("filter", "INPUT", "-j LOG --log-prefix 'iptables-drop: '")?;
        ipt.append("filter", "INPUT", "-j DROP")?;

        println!("iptables rules applied successfully.");

        Ok(())
    }
}
