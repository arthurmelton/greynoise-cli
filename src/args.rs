use clap::{Parser, Subcommand};

lazy_static! {
    pub static ref ARGS: Args = Args::parse(); 
}

/// A cli program to check ips
#[derive(Parser, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The ip that you want to check
    pub ip: String,
    
    /// The value you want to get
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// How much noise do they make on the internet
    #[command(subcommand)]
    Noise(NoiseCommand),

    /// The person / company running the ip 
    #[command(subcommand)]
    Riot(RiotCommand),
}

#[derive(Subcommand, Clone)]
pub enum NoiseCommand {
    /// If they make noise on the internet
    Get,
    /// The first time they have been seen 
    FirstSeen,
    /// The last time they have been seen 
    LastSeen,
    /// Has greynoise seen the ip 
    Seen,
    /// What they are doing 
    Tags,
    /// If they finish the tcp handshake or if they use udp 
    Spoofable,
    /// What are they seen as 
    Classification,
    /// What CVEs do they try and exploit 
    Cve,
    /// If the ip is a bot 
    Bot,
    /// Is the ip a VPN 
    Vpn,
    /// What VPN service are they
    VpnService,
    /// Information about the ip
    #[command(subcommand)]
    Metadata(NoiseMetadata),
    /// Information about what they scan
    #[command(subcommand)]
    Scan(NoiseScan),
    /// Information about what they try and look for / get
    #[command(subcommand)]
    Web(NoiseWeb),
}

#[derive(Subcommand, Clone)]
pub enum NoiseMetadata {
    /// The ID of the matchine
    Asn,
    /// The city the IP lives in
    City,
    /// The country where the IP lives
    Country,
    /// The Country code that the IP lives in
    CountryCode,
    /// The organization that the ip is under
    Organization,
    /// The category for the ip or what it does
    Category,
    /// If the IP is involved with tor
    Tor,
    /// The reverse dns of the ip
    Rdns,
    /// The operating system the matchine is running
    Os,
    /// The countries that they target
    DestinationCountries,
    /// The countries that they target but the country codes
    DestinationCountryCodes,
}

#[derive(Subcommand, Clone)]
pub enum NoiseScan {
    /// Get all the ports that the ip scans
    GetPorts,
    /// Get all the protocols the ip uses
    GetProtocols,
    /// Get all the data
    GetAll,
}

#[derive(Subcommand, Clone)]
pub enum NoiseWeb {
    /// Get all the paths that the ip looks for
    GetPaths,
    /// Get all the useragents the ip uses
    GetUseragents,
}

#[derive(Subcommand, Clone)]
pub enum RiotCommand {
    /// Get what the ip is used for
    Category,
    /// The name of the company / person that operates the ip
    Name,
    /// The description of the company / person
    Description,
    /// The explanation of the category
    Explanation,
    /// The time that the Riot profile was last updated or varified
    LastUpdate,
    /// The url to there logo
    LogoUrl,
    /// The reference to where the information about the company was obtained
    Reference,
    /// How trustworthy is the company / person and if you can ignore there requests
    TrustLevel,
}
