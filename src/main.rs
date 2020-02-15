use dns_parser::rdata::a::Record;
use dns_parser::{Builder, Error as DNSError, Packet, RData, ResponseCode};
use dns_parser::{QueryClass, QueryType};
use io::Result as ioResult;
use log::*;
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use std::error::Error;
use std::net::SocketAddr;
use std::str;
use tokio::net::UdpSocket;
use tokio::prelude::*;

///
/// Simple dns proxy. For the first version, we'll just listen to
/// an UDP socket, parse an incoming DNS query and write the output
/// to the console.
///
/// Next steps:
///   Support TCP protocol
///   Keep track of hosts (and subhosts queried)
///   Allow resolving through local host file
///   Add error handling
///
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();

    info!("Starting server, setting up listener for port 12345");

    // chain the await calls using '?'
    let listen_socket = create_udp_socket_receiver("0.0.0.0:12345").await?;
    let sender_socket = create_udp_socket_sender().await?;
    // let forward_socket = create_udp_socket_receiver("8.8.8.8:53").await?;

    start_listening_udp(listen_socket, sender_socket).await?;
    Ok(())
}

///
/// Create an async UDP socket.
///
async fn create_udp_socket_receiver(host: &str) -> ioResult<UdpSocket> {
    debug!("initializing listener udp socket on {}", host);
    let socket = UdpSocket::bind(&host).await?;
    return Ok(socket);
}

///
/// Create the sender to forward the UDP request
///
async fn create_udp_socket_sender() -> ioResult<UdpSocket> {
    let local_address = "0.0.0.0:0";
    let socket = UdpSocket::bind(local_address).await?;
    let socket_address: SocketAddr = "8.8.8.8:53"
        .parse::<SocketAddr>()
        .expect("Invalid forwarding address specified");
    socket.connect(&socket_address).await?;
    debug!("initializing listener udp socket on {}", local_address);
    return Ok(socket);
}

///
/// Asynchronously run the handling of incoming messages. Whenever something comes in on the socket_rcv_from
/// we try and convert it to a DNS query, and log it to the output. UDP is a connectionless protocol, so we
/// can use this socket to send and receive messages to our client and other servers.
///
async fn start_listening_udp(
    mut listen_socket: UdpSocket,
    mut sender_socket: UdpSocket,
) -> ioResult<()> {
    // 1. Wait for a request from a DNS client.
    // 2. Then forward the request to a remote dns server
    // 3. The response from the remote DNS server is then send back to the initial client.
    loop {
        let (request, peer) = receive_request(&mut listen_socket).await?;
        let forward_response = forward_request(&mut sender_socket, &request[..]).await?;
        listen_socket.send_to(&forward_response[..], &peer).await?;
    }
}

///
/// Forward a request to the provided UDP socket, and wait for an answer.
///
async fn forward_request(sender_socket: &mut UdpSocket, request: &[u8]) -> ioResult<Vec<u8>> {
    let mut buf = [0; 4096];
    info!("Forwarding to target DNS");
    sender_socket.send(request).await?;
    let (amt, _) = sender_socket.recv_from(&mut buf).await?;
    let filled_buf = &mut buf[..amt];
    // let answer_received = parse_incoming_stream(filled_buf).expect("Something went wrong");

    let v = Vec::from(filled_buf);
    return Ok(v);
}

///
/// Receive a request on the reference to the socket. We're not the owner, but we need a mutable
/// reference. The result is a Vec, and the response address. Both are copies, which can be safely
/// modified.
///
async fn receive_request(from_socket: &mut UdpSocket) -> ioResult<(Vec<u8>, SocketAddr)> {
    let mut buf = [0; 4096];

    let (amt, peer) = from_socket.recv_from(&mut buf).await?;
    let filled_buf = &mut buf[..amt];
    // info!("Received length {}", amt);
    // let packet_received = parse_incoming_stream(filled_buf).expect("Something went wrong");
    // info!("Received package {:?}", packet_received);

    let v = Vec::from(filled_buf);
    return Ok((v, peer));
}

///
/// Parse the packet and return it
///
// fn parse_incoming_stream(incoming: &[u8]) -> Result<Packet, DNSError> {
//     let pkt = Packet::parse(incoming)?;
//     return Ok(pkt);
// }

///
/// Initializes the logging library. We just simply log to console
///
fn init_logging() {
    TermLogger::init(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap();
}
