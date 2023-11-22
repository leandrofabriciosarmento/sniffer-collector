
use std::collections::HashMap;
use std::fs::{File};
use std::io::{BufRead, BufReader};
use crate::models::{Config, ServerConfig, SnifferConfig, LogConfig, Interface, Header};
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref LAST_FILE_NAME: Mutex<String> = Mutex::new(String::new());
}


pub(crate) fn read_properties_file(filename: &str) -> Result<Config, std::io::Error> {
    let file = File::open(filename)?;

    let mut properties = HashMap::new();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        // Ignorar linhas em branco ou comentadas
        if line.is_empty() || line.starts_with("#") || line.starts_with("!") {
            continue;
        }

        // Dividir a linha em chave e valor
        if let Some(index) = line.find('=') {
            let key = line[..index].trim().to_string();
            let value = line[(index + 1)..].trim().to_string();
            properties.insert(key, value);
        }
    }

    let server = ServerConfig {
        host_http: properties.get("server.host_http").unwrap_or(&"".to_string()).to_string(),
        environment:  properties.get("server.environment").unwrap_or(&"".to_string()).to_string(),
        interface: Interface {
            name: properties.get("server.interface.name").unwrap_or(&"".to_string()).to_string(),
        },
        outputfolder: properties.get("server.outputfolder").unwrap_or(&"".to_string()).to_string(),
    };

    let sniffer = SnifferConfig {
        active: properties.get("sniffer.active").unwrap_or(&"false".to_string()) == "true",
        log: LogConfig {
            max_size_file: properties.get("sniffer.log.max_size_file").unwrap_or(&"0".to_string()).parse().unwrap_or(0),
            verbose: properties.get("sniffer.log.verbose").unwrap_or(&"false".to_string()) == "true",
        },
        header: Header {
            linkedkey: properties.get("sniffer.header.linkedkey").unwrap_or(&"".to_string()).to_string(),
        },
        ports: match properties.get("sniffer.ports") {
            Some(ports_str) => ports_str.split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect(),
            None => Vec::new(),
        },

    };

    let component_name = properties.get("component_name").unwrap_or(&"".to_string()).to_string();

    Ok(Config { component_name, server, sniffer })
}