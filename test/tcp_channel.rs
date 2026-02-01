use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use anyhow::Result;

use circuit_psi::tcp_channel::TcpChannel;

fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(())
}

#[test]
fn tcp_channel_roundtrip_localhost() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let msg_small = b"hello from client".to_vec();
    let msg_large: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    let reply = b"hello from server".to_vec();

    let server_small = msg_small.clone();
    let server_large = msg_large.clone();
    let server_reply = reply.clone();

    let server_handle = thread::spawn(move || -> Result<()> {
        let (stream, _) = listener.accept()?;
        configure_stream(&stream)?;
        let mut channel = TcpChannel::new(stream);

        let got_small = channel.receive()?;
        assert_eq!(got_small, server_small);

        let got_large = channel.receive()?;
        assert_eq!(got_large, server_large);

        channel.send(&server_reply)?;
        Ok(())
    });

    let client_stream = TcpStream::connect(addr)?;
    configure_stream(&client_stream)?;
    let mut client = TcpChannel::new(client_stream);

    client.send(&msg_small)?;
    client.send(&msg_large)?;

    let got_reply = client.receive()?;
    assert_eq!(got_reply, reply);

    server_handle.join().expect("server thread panicked")?;
    Ok(())
}
