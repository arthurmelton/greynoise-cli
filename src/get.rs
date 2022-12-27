#![allow(non_snake_case)]

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Response {
    pub ip: String,
    pub metadata: IpMetadata,
    pub riotProfile: RiotProfile,
    pub noiseProfile: NoiseProfile,
}

#[derive(Deserialize)]
pub struct IpMetadata {
    pub riot: IpRiotMetadata,
    pub noise: IpNoiseMetadata,
}

#[derive(Deserialize)]
pub struct IpRiotMetadata {
    pub found: bool,
}

#[derive(Deserialize)]
pub struct IpNoiseMetadata {
    pub found: bool,
}

#[derive(Deserialize)]
pub struct RiotProfile {
    pub category: String,
    pub name: String,
    pub description: String,
    pub explanation: String,
    pub lastUpdated: String,
    pub logoUrl: String,
    pub reference: String,
    pub trustLevel: String,
}

#[derive(Deserialize)]
pub struct NoiseProfile {
    pub ip: String,
    pub firstSeen: String,
    pub lastSeen: String,
    pub seen: bool,
    pub tags: Option<Vec<String>>,
    pub tagIds: Option<Vec<String>>,
    pub actor: String,
    pub spoofable: bool,
    pub classification: String,
    pub cve: Option<Vec<String>>,
    pub bot: bool,
    pub vpn: bool,
    pub vpnService: String,
    pub metadata: NoiseMetadata,
    pub rawData: NoiseRawData,
}

#[derive(Deserialize)]
pub struct NoiseMetadata {
    pub asn: String,
    pub city: String,
    pub country: String,
    pub countryCode: String,
    pub organization: String,
    pub category: String,
    pub tor: bool,
    pub rdns: String,
    pub os: String,
    pub destinationCountries: Option<Vec<String>>,
    pub destinationCountryCodes: Option<Vec<String>>,
    pub sourceCountry: String,
    pub sourceCountryCode: String,
}

#[derive(Deserialize)]
pub struct NoiseRawData {
    pub scan: Option<Vec<ScanItem>>,
    pub web: WebItem,
    pub ja3: Option<Vec<String>>,
    pub haash: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct ScanItem {
    pub port: u16,
    pub protocol: Option<String>,
}

#[derive(Deserialize)]
pub struct WebItem {
    pub paths: Option<Vec<String>>,
    pub useragents: Option<Vec<String>>,
}

pub fn get(ip: String) -> Result<Response, ureq::Error> {
    let body: Response = ureq::get(&format!("https://viz.greynoise.io/api/v3/internal/ip/{}", ip))
        .set("user-agent", &format!("greynoise-cli/{} (https://git.arthurmelton.com/greynoise-cli)", env!("CARGO_PKG_VERSION")))
        .call()?
        .into_json()?;
    Ok(body)
}
