mod file_utils;
mod models;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::thread;
use std::time::UNIX_EPOCH;
use chrono::Utc;
use pcap::{Device, Capture, Active};
use crate::file_utils::{read_properties_file};
use crate::models::{Config, EthernetFrame, IPv4Packet};
use local_ip_address::list_afinet_netifas;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    //Carrega as informações do arquivo de configuraçẽos
    pub static ref CONFIG: Config = {
        match read_properties_file("config.properties") {
            Ok(config_read) => config_read,
            Err(err) => {
                eprintln!("Erro ao ler configurações: {}", err);
                std::process::exit(1);
            }
        }
    };
    //Define o tamanho máximo do arquivo de log
    pub static ref FILE_SIZE_LIMIT: u64 = (&CONFIG.sniffer.log.max_size_file * 1024 * 1024) as u64;
}

fn main() {
    println!("CONFIG: {:?}", *CONFIG);
    init_pcap();
}

fn init_pcap(){

    // Verifica se o sniffer está ativo
    if !CONFIG.sniffer.active {
        return;
    }

    // Observa todas as interfaces de rede
    if CONFIG.server.interface.name.is_empty() {
        for device in Device::list().unwrap() {
            sniffer_network_interface(device);
        }
    }else{ // Observa somente a interface indicada nas configurações
        let main_device =  Device::from(&*CONFIG.server.interface.name);
        thread::spawn(|| {
            sniffer_network_interface(main_device);
        });
    }
}

// Função que captura os pacotes de rede
fn sniffer_network_interface(main_device: Device) {

    let network_interfaces = list_afinet_netifas().unwrap();

    // Verifica o IP da interface de rede
    let mut ip_addres: String = String::new();
    for add in main_device.clone().addresses {
        if /*(name.to_string() == main_device.name.to_string()
            && Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap().is_match(&*ip.to_string()) )
            || */add.addr.to_string() == CONFIG.server.interface.ip.to_string() {
            ip_addres = add.addr.to_string();
            println!("Listenner: {:?}", main_device);
            break;
        }
    }

    // se ip_addres for vazio, percorre a lista de ip de main_device e compara
    // com o ip do arquivo de configuração
    if ip_addres.is_empty() {
         return;
    }


    let mut cap = Capture::from_device(main_device).unwrap()
        .promisc(true)
        .snaplen(5000)
        .open().unwrap();

    percorrer_pacotes(&mut ip_addres, &mut cap);
}

// Percorre os pacotes de rede
fn percorrer_pacotes(mut ip_addres: &mut String, cap: &mut Capture<Active>) {

    // Cria o arquivo de log
    let mut file: BufWriter<File> = create_new_file_log().expect("ERR: create_new_file_log().expect");

    // Loop infinito para capturar os pacotes
    while let Ok(packet) = cap.next_packet() {

        // Verifica se o pacote é IPv4 e cria um objeto IPv4Packet utilizando o pacote de rede
        if let Some(mut ipv4_packet) = EthernetFrame::new(&packet.data) {

            // Adiciona informações extras ao pacote
            adicionar_informacoes_extras(&mut ip_addres, &mut ipv4_packet);

            // Obtem o timestamp do pacote
            let timestamp = match ipv4_packet.time.duration_since(UNIX_EPOCH) {
                Ok(duration) => duration,
                Err(_) => std::time::Duration::new(0, 0)
            };

            // Texto formatado para o arquivo de log
            let formatted_text = format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                                         ipv4_packet.environment,
                                         ipv4_packet.component_name,
                                         ipv4_packet.host_http,
                                         ipv4_packet.direction,
                                         ipv4_packet.source_ip,
                                         ipv4_packet.destination_ip,
                                         ipv4_packet.http_resource,
                                         ipv4_packet.linkedkey,
                                         timestamp.as_secs());

            if file.get_ref().metadata().expect("ERR: file.get_ref().metadata().expect").len() > *FILE_SIZE_LIMIT {
                file = create_new_file_log().expect("");
            }

            file.write_all(formatted_text.as_bytes()).expect("ERR: file.write_all.expect");
            file.flush().expect("ERR: file.flush().expect");

            verbose(&ipv4_packet);
        }
    }
}

// Adiciona informações extras ao pacote
fn adicionar_informacoes_extras(ip_addres: &mut String, ipv4_packet: &mut IPv4Packet) {
    ipv4_packet.server_ip = ip_addres.to_string();
    // Define se o pacote é de entrada ou saída
    ipv4_packet.direction = if ip_addres.to_string() == ipv4_packet.source_ip.to_string() { "OUT" } else { "IN" }.to_string();
}

fn create_new_file_log() -> std::io::Result<BufWriter<File>> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let file_name = format!("{}output_{}_{}.lws",
                            &*CONFIG.server.outputfolder.to_string(),
                            &*CONFIG.component_name.to_string(),
                            timestamp);
    let file = File::create(Path::new(&file_name))?;
    println!("Arquivo {} criado!\n", file_name);
    Ok(BufWriter::new(file))
}

fn verbose(ipv4_packet: &IPv4Packet) {
    if !CONFIG.sniffer.log.verbose {
        return;
    }
    println!("Time: {:?}", ipv4_packet.time);
    println!("IPv4 Version: {}", ipv4_packet.version);
    println!("Header Length: {} bytes", ipv4_packet.header_length);
    println!("Total Length: {} bytes", ipv4_packet.total_length);
    println!("TTL: {}", ipv4_packet.ttl);
    println!("Protocol: {}", ipv4_packet.protocol);
    println!("Source IP: {}", ipv4_packet.source_ip);
    println!("Destination IP: {}", ipv4_packet.destination_ip);

    println!("Componente: {}", ipv4_packet.component_name);
    println!("ServerName: {}", ipv4_packet.host_http);
    println!("Source Port: {}", ipv4_packet.source_port);
    println!("Destination Port: {}", ipv4_packet.destination_port);
    println!("Header: {}", ipv4_packet.http_resource);
    println!("LinkedKey: {}", ipv4_packet.linkedkey);
    println!("Direction: {}", ipv4_packet.direction);
    println!("Server IP: {}", ipv4_packet.server_ip);

    println!("--------------------------------------------------------------------------\n\n");
}


