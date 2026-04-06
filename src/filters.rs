pub struct Filters {
    pub proto: Vec<String>,
    pub port: Vec<u16>,
    pub ip: Vec<String>,
    pub exc_proto: Vec<String>,
    pub exc_port: Vec<u16>,
    pub exc_ip: Vec<String>,
    pub no_mac: bool,
}
