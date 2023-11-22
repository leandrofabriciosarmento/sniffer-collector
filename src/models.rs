use std::time::{SystemTime};
use crate::CONFIG;

#[derive(Debug)]
pub struct Config {
    pub(crate) component_name: String,
    pub(crate) server: ServerConfig,
    pub(crate) sniffer: SnifferConfig,
}

#[derive(Debug)]
pub(crate) struct ServerConfig {
    pub(crate) host_http: String,
    pub(crate) environment: String,
    pub(crate) interface: Interface,
    pub(crate) outputfolder: String,
}

#[derive(Debug)]
pub(crate) struct SnifferConfig {
    pub(crate) active: bool,
    pub(crate) ports: Vec<u16>,
    pub(crate) log: LogConfig,
    pub(crate) header: Header,
}

#[derive(Debug)]
pub(crate) struct Header {
    pub(crate) linkedkey: String,
}

#[derive(Debug)]
pub(crate) struct Interface {
    pub(crate) name: String,
}

#[derive(Debug)]
pub(crate) struct LogConfig {
    pub(crate) max_size_file: u32,
    pub(crate) verbose: bool,
}

#[derive(Debug)]
pub enum EthernetFrame {}

#[derive(Debug)]
pub struct IPv4Packet {
    pub(crate) version: u8,
    pub(crate) header_length: u8,
    pub(crate) total_length: u16,
    pub(crate) ttl: u8,
    pub(crate) protocol: u8,
    pub(crate) source_ip: String,
    pub(crate) destination_ip: String,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) http_resource: String,
    pub(crate) time: SystemTime,
    pub(crate) server_ip: String,
    pub(crate) direction: String,
    pub(crate) linkedkey: String,
    pub(crate) component_name: String,
    pub(crate) environment: String,
    pub(crate) host_http: String
}

impl EthernetFrame {
    pub(crate) fn new(packet: &[u8]) -> Option<IPv4Packet> {
        if packet.len() < 14 {
            return None;
        }

        let ether_type = u16::from_be_bytes([packet[12], packet[13]]);

        match ether_type {
            0x0800 => {
                if let Some(ipv4_packet) = IPv4Packet::new(&packet[14..]) {
                    Some(ipv4_packet)
                } else {
                    None
                }
            }
            0x86DD => {
                // Implemente a extração de informações para IPv6 aqui
                // Se necessário, você pode criar um struct IPv6Packet semelhante ao IPv4Packet
                None
            }
            // Adicione mais casos para outros tipos de pacotes, como UDP, ICMP, etc.
            _ => None,
        }
    }
}

fn get_ipv4_header_length(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 {
        // Um cabeçalho IPv4 tem no mínimo 20 bytes, portanto, se o pacote for menor,
        // algo está errado.
        return None;
    }

    // Obtenha o primeiro byte do cabeçalho IPv4.
    let first_byte = packet[0];

    // Obtenha os 4 bits mais baixos do primeiro byte (IHL).
    let ihl = first_byte & 0x0F;

    // Calcule o tamanho real do cabeçalho IPv4 em bytes.
    let header_length = ihl as usize * 4;

    if header_length < 20 || header_length > packet.len() {
        //println!("Tamanho de cabeçalho ({:?}) inválido, algo está errado.", header_length);
        return None;
    }

    Some(header_length)
}

fn find_subarray(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn extract_resource_http(packet: &[u8]) -> Result<String, String> {

    let http_start_index = match find_subarray(&packet, &[71, 69, 84]) {//GET
        Some(index) => index,
        None => match find_subarray(&packet, &[80, 79, 83, 84]) {//POST
            Some(index) => index,
            None => match find_subarray(&packet, &[80, 85, 84]) {//PUT
                Some(index) => index,
                None => match find_subarray(&packet, &[68, 69, 76, 69, 84, 69]) {//DELETE
                    Some(index) => index,
                    None => 99999,
                },
            },
        }
    };

    let index_fim_header = match find_subarray(&packet, &[13, 10]) { //  \r\n
        Some(index) => index,
        None => 99999
    };

    if http_start_index != 99999 && index_fim_header != 99999 {
        let http_data = &packet[http_start_index..index_fim_header];
        //Obtem a parte do meio do texto "GET /recurso_chamado HTTP/1.1"
        let http_text = String::from_utf8_lossy(http_data).to_string().split(" ").collect::<Vec<&str>>()[1].to_string();
        Ok(http_text)
    } else {
        Err("Cabecalho http nao encontrado.".to_string())
    }

}

pub fn extract_linkedkey(packet: &[u8], linkedkey_byte_array: &[u8]) -> Result<String, String> {

    //println!("linkedkey_byte_array: {:?}", String::from_utf8_lossy(linkedkey_byte_array));
    let http_start_index = match find_subarray(&packet, linkedkey_byte_array) {
        Some(index) => index,
        None => 99999,
    };


    if http_start_index != 99999 {
        let index_fim_header = match find_subarray(&packet[http_start_index..], &[13, 10]) { //  \r\n
            Some(index) => index,
            None => 99999
        };
        if index_fim_header != 99999 {
            let http_data = &packet[http_start_index..http_start_index+index_fim_header];
            let http_text = String::from_utf8_lossy(http_data).to_string();
            // Tenta converter os dados HTTP para uma String UTF-8.
            Ok(http_text)
        } else {
            Err("Linkedkey nao encontrado.".to_string())
        }
    } else {
        Err("Linkedkey nao encontrado.".to_string())
    }

}

impl IPv4Packet {
    fn new(packet: &[u8]) -> Option<IPv4Packet> {
        if packet.len() < 20 {
            return None;
        }

        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }
        //println!("packet: {:?}", packet);

        let header_length: u8 = get_ipv4_header_length(packet).unwrap() as u8;
        let total_length = u16::from_be_bytes([packet[2], packet[3]]);
        let ttl = packet[8];
        let protocol = packet[9];
        let source_ip = format!("{}.{}.{}.{}", packet[12], packet[13], packet[14], packet[15]);
        let destination_ip = format!("{}.{}.{}.{}", packet[16], packet[17], packet[18], packet[19]);
        let now = SystemTime::now();
        let servver_ip = String::new();

        let payload = &packet[header_length as usize..];

        // Verifique se o protocolo é TCP (valor 6 para TCP)
        if protocol == 6 {
            // Analise o cabeçalho TCP e extraia informações relevantes
            let source_port: u16 = u16::from_be_bytes([payload[0], payload[1]]);
            let destination_port: u16 = u16::from_be_bytes([payload[2], payload[3]]);

            let mut is_port_sniffer: bool = false;
            for &port in &CONFIG.sniffer.ports {
                if port == destination_port || port == source_port {
                    is_port_sniffer = true;
                    break; // Sai do loop assim que encontra uma correspondência
                }
            }

            // verificar se é um dos portas configuradas para o sniffer
            if is_port_sniffer {


                // Aqui, você pode continuar a análise do tráfego HTTP
                // Dependendo do que você deseja extrair, pode ser necessário implementar a lógica
                // para analisar o cabeçalho HTTP e o corpo da mensagem.
                // Por exemplo, você pode procurar por sequências como "GET", "POST", etc.

                let txt_resource = match extract_resource_http(&packet) {
                    Ok(http_string) => http_string,
                    Err(_e) => "".to_string(),
                };

                //println!("header: {:?}", tst_header);

                let linkedkey: String =
                    match extract_linkedkey(
                        &packet,
                        &CONFIG.sniffer.header.linkedkey.to_string().as_bytes()) {
                        Ok(str_found) => str_found,
                        Err(_e) => match extract_linkedkey(
                            &packet,
                            &CONFIG.sniffer.header.linkedkey.to_string().to_uppercase().as_bytes()) {
                            Ok(str_found) => str_found,
                            Err(_e) => match extract_linkedkey(
                                &packet,
                                &CONFIG.sniffer.header.linkedkey.to_string().to_lowercase().as_bytes()) {
                                Ok(str_found) => str_found,
                                Err(_e) => "".to_string(),
                            },
                        },
                    };

                if txt_resource.len() > 0 {
                    Some(IPv4Packet {
                        version,
                        header_length,
                        total_length,
                        ttl,
                        protocol,
                        source_ip,
                        destination_ip,
                        source_port,
                        destination_port,
                        http_resource: txt_resource.to_string(),
                        time: now,
                        server_ip: servver_ip,
                        direction: "".to_string(),
                        linkedkey: linkedkey.to_string(),
                        component_name: CONFIG.component_name.to_string(),
                        environment: CONFIG.server.environment.to_string(),
                        host_http: CONFIG.server.host_http.to_string(),
                    })
                } else {
                    // Não é tráfego HTTP que intresse
                    None
                }
            } else {
                // Não é tráfego HTTP
                None
            }
        } else {
            // Não é tráfego TCP
            None
        }
    }
}