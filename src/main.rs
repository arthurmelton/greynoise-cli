#[macro_use]
extern crate lazy_static;

mod get;
mod args;

use args::*;

fn main() {
    let args = ARGS.clone();
    match get::get(args.ip) {
        Ok(data) => {
            match args.command {
                Commands::Noise(noise) => match noise {
                    NoiseCommand::Get => println!("{}", data.metadata.noise.found),
                    NoiseCommand::FirstSeen => print_value_maybe_none(data.noiseProfile.firstSeen, "noise"),
                    NoiseCommand::LastSeen => print_value_maybe_none(data.noiseProfile.lastSeen, "noise"),
                    NoiseCommand::Seen => println!("{}", data.noiseProfile.seen),
                    NoiseCommand::Tags => match data.noiseProfile.tags {
                        Some(tags) => match tags.len() {
                            0 => return_error("There are no tags for this ip"),
                            _ => println!("{}", tags.join("\n"))
                        },
                        None => return_error("There are no tags for this ip"),
                    },
                    NoiseCommand::Spoofable => println!("{}", data.noiseProfile.spoofable),
                    NoiseCommand::Classification => print_value_maybe_none(data.noiseProfile.classification, "noise"),
                    NoiseCommand::Cve => match data.noiseProfile.cve {
                        Some(cve) => match cve.len() {
                            0 => return_error("There are no CVEs for this ip"),
                            _ => println!("{}", cve.join("\n"))
                        },
                        None => return_error("There are no CVEs for this ip"),
                    },
                    NoiseCommand::Bot => println!("{}", data.noiseProfile.bot),
                    NoiseCommand::Vpn => println!("{}", data.noiseProfile.vpn),
                    NoiseCommand::VpnService => print_value_maybe_none(data.noiseProfile.vpnService, "noise"),
                    NoiseCommand::Metadata(metadata) => match metadata {
                        NoiseMetadata::Asn => print_value_maybe_none(data.noiseProfile.metadata.asn, "noise"),
                        NoiseMetadata::City => print_value_maybe_none(data.noiseProfile.metadata.city, "noise"),
                        NoiseMetadata::Country => print_value_maybe_none(data.noiseProfile.metadata.country, "noise"),
                        NoiseMetadata::CountryCode => print_value_maybe_none(data.noiseProfile.metadata.countryCode, "noise"),
                        NoiseMetadata::Organization => print_value_maybe_none(data.noiseProfile.metadata.organization, "noise"),
                        NoiseMetadata::Category => print_value_maybe_none(data.noiseProfile.metadata.category, "noise"),
                        NoiseMetadata::Tor => println!("{}", data.noiseProfile.metadata.tor),
                        NoiseMetadata::Rdns => print_value_maybe_none(data.noiseProfile.metadata.rdns, "noise"),
                        NoiseMetadata::Os => print_value_maybe_none(data.noiseProfile.metadata.os, "noise"),
                        NoiseMetadata::DestinationCountries => match data.noiseProfile.metadata.destinationCountries {
                            Some(countries) => match countries.len() {
                                0 => return_error("There are no destination countries for this ip"),
                                _ => println!("{}", countries.join("\n"))
                            },
                            None => return_error("There are no destination countries for this ip"),
                        },
                        NoiseMetadata::DestinationCountryCodes => match data.noiseProfile.metadata.destinationCountryCodes {
                            Some(countries) => match countries.len() {
                                0 => return_error("There are no destination countries for this ip"),
                                _ => println!("{}", countries.join("\n"))
                            },
                            None => return_error("There are no destination countries for this ip"),
                        },
                    },
                    NoiseCommand::Scan(scan) => match scan {
                        NoiseScan::GetPorts => match data.noiseProfile.rawData.scan {
                            Some(scan) => match scan.len() {
                                0 => return_error("There are no ports scanned for this ip"),
                                _ => println!("{}", scan.iter().map(|x| x.port.to_string() ).collect::<Vec<_>>().join("\n"))
                            }
                            None => return_error("There are no ports scanned for this ip")
                        },
                        NoiseScan::GetProtocols => match data.noiseProfile.rawData.scan {
                            Some(scan) => {
                                let mut protocols = scan.iter().filter_map(|x| x.protocol.clone() ).collect::<Vec<String>>();
                                protocols.sort();
                                protocols.dedup();
                                match protocols.len() {
                                    0 => return_error("There are no protocols for this ip"),
                                    _ => println!("{}", protocols.join("\n"))
                                }
                            }
                            None => return_error("There are no protocols for this ip")
                        },
                        NoiseScan::GetAll => match data.noiseProfile.rawData.scan {
                            Some(scan) => match scan.len() {
                                0 => return_error("There are no ports scanned for this ip"),
                                _ => println!("{}", scan.iter().map(|x| format!("{}, {}", x.port, x.protocol.clone().unwrap_or("None".to_string()))).collect::<Vec<String>>().join("\n"))
                            }
                            None => return_error("There are no ports scanned for this ip")
                        }
                    },
                    NoiseCommand::Web(web) => match web {
                        NoiseWeb::GetPaths => match data.noiseProfile.rawData.web.paths {
                            Some(paths) => match paths.len() {
                                0 => return_error("There are no paths scanned by ip"),
                                _ => println!("{}", paths.join("\n"))
                            }
                            None => return_error("There are no paths scanned by ip")
                        },
                        NoiseWeb::GetUseragents => match data.noiseProfile.rawData.web.useragents {
                            Some(useragents) => match useragents.len() {
                                0 => return_error("There are no paths scanned by ip"),
                                _ => println!("{}", useragents.join("\n"))
                            }
                            None => return_error("There are no paths scanned by ip")
                        }
                    },
                },
                Commands::Riot(riot) => match riot {
                    RiotCommand::Category => print_value_maybe_none(data.riotProfile.category, "riot"),
                    RiotCommand::Name => print_value_maybe_none(data.riotProfile.name, "riot"),
                    RiotCommand::Description => print_value_maybe_none(data.riotProfile.description, "riot"),
                    RiotCommand::Explanation => print_value_maybe_none(data.riotProfile.explanation, "riot"),
                    RiotCommand::LastUpdate => print_value_maybe_none(data.riotProfile.lastUpdated, "riot"),
                    RiotCommand::LogoUrl => print_value_maybe_none(data.riotProfile.logoUrl, "riot"),
                    RiotCommand::Reference => print_value_maybe_none(data.riotProfile.reference, "riot"),
                    RiotCommand::TrustLevel => print_value_maybe_none(data.riotProfile.trustLevel, "riot"),
                },
            }
        },
        Err(_) => return_error("Could not find information about this ip")
    }
}

fn return_error(message: &str) {
    eprintln!("{}", message);
    std::process::exit(1);
}

fn print_value_maybe_none(value: String, under: &str) {
    match &value as &str {
        "" => return_error(&format!("Could not find any data for this, make sure that {} was found.\ngn {} {} get", under, ARGS.clone().ip, under)),
        _ => println!("{}", value),
    }
}
