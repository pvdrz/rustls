use std::fs;
use std::sync::Arc;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use rustls::crypto::ring::Ring;
use rustls::crypto::CryptoProvider;
use rustls::{OwnedTrustAnchor, RootCertStore};

fn start_connection(
    config: &Arc<rustls::ClientConfig<impl CryptoProvider>>,
    domain_name: &str,
    port: u16,
) {
    let server_name = domain_name
        .try_into()
        .expect("invalid DNS name");
    let mut conn = rustls::ClientConnection::new(Arc::clone(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{}:{}", domain_name, port)).unwrap();
    sock.set_nodelay(true).unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        domain_name
    );

    // If early data is available with this server, then early_data()
    // will yield Some(WriteEarlyData) and WriteEarlyData implements
    // io::Write.  Use this to send the request.
    if let Some(mut early_data) = conn.early_data() {
        early_data
            .write_all(request.as_bytes())
            .unwrap();
        println!("  * 0-RTT request sent");
    }

    let mut stream = rustls::Stream::new(&mut conn, &mut sock);

    // Complete handshake.
    stream.flush().unwrap();

    // If we didn't send early data, or the server didn't accept it,
    // then send the request as normal.
    if !stream.conn.is_early_data_accepted() {
        stream
            .write_all(request.as_bytes())
            .unwrap();
        println!("  * Normal request sent");
    } else {
        println!("  * 0-RTT data accepted");
    }

    let mut first_response_line = String::new();
    BufReader::new(stream)
        .read_line(&mut first_response_line)
        .unwrap();
    println!("  * Server response: {:?}", first_response_line);
}

fn main() {
    let hostname;
    let port;

    let args = std::env::args().collect::<Vec<String>>();
    let cafile_path = args.get(1);

    env_logger::init();

    let mut root_store = RootCertStore::empty();

    if let Some(cafile) = cafile_path {
        let certfile = fs::File::open(cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(rustls_pemfile::certs(&mut reader).unwrap());

        hostname = "localhost";
        port = 1443;
    } else {
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }),
        );
        hostname = "jbp.io";
        port = 443;
    }

    let mut config = rustls::ClientConfig::<Ring>::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Enable early data.
    config.enable_early_data = true;
    let config = Arc::new(config);

    // Do two connections. The first will be a normal request, the
    // second will use early data if the server supports it.

    println!("* Sending first request:");
    start_connection(&config, hostname, port);
    println!("* Sending second request:");
    start_connection(&config, hostname, port);
}
