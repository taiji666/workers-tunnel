use crate::proxy::{parse_early_data, parse_user_id, run_tunnel};
use crate::websocket::WebSocketStream;
use wasm_bindgen::JsValue;
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    // get user id
    let user_id = env.var("USER_ID")?.to_string();
    let parsed_user_id = parse_user_id(&user_id).map_err(Error::from)?;

    // get proxy ip list
    let proxy_ip = env.var("PROXY_IP")?.to_string();
    let proxy_ip = proxy_ip
        .split_ascii_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    // better disguising;
    let fallback_site = env
        .var("FALLBACK_SITE")
        .unwrap_or(JsValue::from_str("").into())
        .to_string();
    let is_websocket_upgrade = req
        .headers()
        .get("Upgrade")?
        .map(|up| up.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    // show uri
    let show_uri = env.var("SHOW_URI")?.to_string().parse().unwrap_or(false);
    let request_path = req.path().to_string();
    let uuid_str = user_id.clone();
    let host_str = req.url()?.host_str().unwrap().to_string();
    let request_method = req.method().to_string();

    if !is_websocket_upgrade && show_uri && request_path.contains(uuid_str.as_str()) {
        let vless_uri = format!(
            "vless://{uuid}@{host}:443?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=%2Fws%3Fed%3D2048#workers-tunnel",
            uuid = uuid_str,
            host = host_str
        );
        return Response::ok(vless_uri);
    }

    if !is_websocket_upgrade && !fallback_site.is_empty() {
        let req = Fetch::Url(Url::parse(&fallback_site)?);
        return req.send().await;
    }

    if !is_websocket_upgrade {
        console_log!(
            "non-websocket request rejected: method={}, path={}, host={}",
            request_method,
            request_path,
            host_str
        );
        return Response::error("websocket upgrade required", 426);
    }

    // ready early data
    let early_data = req.headers().get("sec-websocket-protocol")?;
    let early_data = parse_early_data(early_data)?;
    let early_data_len = early_data.as_ref().map(|data| data.len()).unwrap_or(0);

    console_log!(
        "websocket request accepted: method={}, path={}, host={}, early_data_len={}, proxy_ip_count={}",
        request_method,
        request_path,
        host_str,
        early_data_len,
        proxy_ip.len()
    );

    // Accept / handle a websocket connection
    let WebSocketPair { client, server } = WebSocketPair::new()?;
    server.accept()?;

    wasm_bindgen_futures::spawn_local(async move {
        // create websocket stream
        let socket = WebSocketStream::new(
            &server,
            server.events().expect("could not open stream"),
            early_data,
        );

        // into tunnel
        if let Err(err) = run_tunnel(socket, parsed_user_id, proxy_ip).await {
            // log error
            console_error!("error: {}", err);

            // close websocket connection
            _ = server.close(Some(1003), Some("invalid request"));
        }
    });

    Response::from_websocket(client)
}

#[allow(dead_code)]
mod protocol {
    pub const VERSION: u8 = 0;
    pub const RESPONSE: [u8; 2] = [VERSION, 0];
    pub const COMMAND_TCP: u8 = 1;
    pub const COMMAND_UDP: u8 = 2;
    pub const COMMAND_MUX: u8 = 3;
    pub const ADDRESS_TYPE_IPV4: u8 = 1;
    pub const ADDRESS_TYPE_DOMAIN: u8 = 2;
    pub const ADDRESS_TYPE_IPV6: u8 = 3;
}

mod proxy {
    use std::io::{Error, ErrorKind, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::ext::StreamExt;
    use crate::protocol;
    use crate::websocket::WebSocketStream;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
    use uuid::Uuid;
    use worker::*;

    pub type UserId = [u8; 16];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Command {
        Tcp,
        Udp,
        Mux,
    }

    impl TryFrom<u8> for Command {
        type Error = Error;

        fn try_from(value: u8) -> Result<Self> {
            match value {
                protocol::COMMAND_TCP => Ok(Self::Tcp),
                protocol::COMMAND_UDP => Ok(Self::Udp),
                protocol::COMMAND_MUX => Ok(Self::Mux),
                _ => Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("unsupported command: {}", value),
                )),
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct VlessRequest {
        command: Command,
        remote_port: u16,
        remote_addr: String,
    }

    pub fn parse_early_data(data: Option<String>) -> Result<Option<Vec<u8>>> {
        if let Some(data) = data {
            if !data.is_empty() {
                let s = data.replace('+', "-").replace('/', "_").replace("=", "");
                match URL_SAFE_NO_PAD.decode(s) {
                    Ok(early_data) => return Ok(Some(early_data)),
                    Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
                }
            }
        }
        Ok(None)
    }

    pub fn parse_user_id(user_id: &str) -> Result<UserId> {
        Uuid::parse_str(user_id)
            .map(|uuid| *uuid.as_bytes())
            .map_err(|err| Error::new(ErrorKind::InvalidInput, format!("invalid USER_ID: {}", err)))
    }

    async fn read_vless_request<R>(reader: &mut R, user_id: &UserId) -> Result<VlessRequest>
    where
        R: AsyncRead + Unpin,
    {
        let version = reader.read_u8().await?;
        if version != protocol::VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "invalid version"));
        }

        let mut request_user_id = [0u8; 16];
        reader.read_exact(&mut request_user_id).await?;
        if &request_user_id != user_id {
            return Err(Error::new(ErrorKind::InvalidData, "invalid user id"));
        }

        let addons_length = reader.read_u8().await?;
        _ = reader.read_bytes(addons_length as usize).await?;

        let command = Command::try_from(reader.read_u8().await?)?;
        let remote_port = reader.read_u16().await?;
        let remote_addr = read_remote_address(reader).await?;

        Ok(VlessRequest {
            command,
            remote_port,
            remote_addr,
        })
    }

    async fn read_remote_address<R>(reader: &mut R) -> Result<String>
    where
        R: AsyncRead + Unpin,
    {
        match reader.read_u8().await? {
            protocol::ADDRESS_TYPE_DOMAIN => {
                let length = reader.read_u8().await?;
                if length == 0 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "domain address must not be empty",
                    ));
                }
                reader.read_string(length as usize).await
            }
            protocol::ADDRESS_TYPE_IPV4 => {
                Ok(Ipv4Addr::from_bits(reader.read_u32().await?).to_string())
            }
            protocol::ADDRESS_TYPE_IPV6 => Ok(format!(
                "[{}]",
                Ipv6Addr::from_bits(reader.read_u128().await?)
            )),
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid address type")),
        }
    }

    async fn write_response_header<W>(writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_all(&protocol::RESPONSE).await.map_err(|e| {
            Error::new(
                ErrorKind::ConnectionAborted,
                format!("send response header failed: {}", e),
            )
        })
    }

    pub async fn run_tunnel(
        mut client_socket: WebSocketStream<'_>,
        user_id: UserId,
        proxy_ip: Vec<String>,
    ) -> Result<()> {
        let request = read_vless_request(&mut client_socket, &user_id).await?;

        console_log!(
            "tunnel request parsed: command={:?}, remote_addr={}, remote_port={}, fallback_targets={}",
            request.command,
            request.remote_addr,
            request.remote_port,
            if proxy_ip.is_empty() {
                "<none>".to_string()
            } else {
                proxy_ip.join(",")
            }
        );

        // process outbound
        match request.command {
            Command::Tcp => {
                // try to connect to remote
                for target in [vec![request.remote_addr.clone()], proxy_ip].concat() {
                    console_log!(
                        "tcp outbound attempt: target={}, port={}",
                        target,
                        request.remote_port
                    );
                    match process_tcp_outbound(&mut client_socket, &target, request.remote_port)
                        .await
                    {
                        Ok(_) => {
                            console_log!(
                                "tcp outbound connected: target={}, port={}",
                                target,
                                request.remote_port
                            );
                            // normal closed
                            return Ok(());
                        }
                        Err(e) => {
                            console_error!(
                                "tcp outbound failed: target={}, port={}, kind={:?}, error={}",
                                target,
                                request.remote_port,
                                e.kind(),
                                e
                            );
                            // connection reset
                            if e.kind() != ErrorKind::ConnectionReset {
                                return Err(e);
                            }

                            // continue to next target
                            continue;
                        }
                    }
                }

                console_error!(
                    "tcp outbound exhausted all targets: remote_port={}",
                    request.remote_port
                );
                Err(Error::new(ErrorKind::InvalidData, "no target to connect"))
            }
            Command::Udp => {
                console_log!(
                    "udp outbound request: remote_addr={}, remote_port={}",
                    request.remote_addr,
                    request.remote_port
                );
                process_udp_outbound(
                    &mut client_socket,
                    &request.remote_addr,
                    request.remote_port,
                )
                .await
            }
            Command::Mux => Err(Error::new(
                ErrorKind::InvalidData,
                "vless mux is not supported on Cloudflare Workers",
            )),
        }
    }

    async fn process_tcp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        target: &str,
        port: u16,
    ) -> Result<()> {
        // connect to remote socket
        let mut remote_socket = Socket::builder().connect(target, port).map_err(|e| {
            Error::new(
                ErrorKind::ConnectionAborted,
                format!("connect to remote failed: {}", e),
            )
        })?;

        // check remote socket
        remote_socket.opened().await.map_err(|e| {
            Error::new(
                ErrorKind::ConnectionReset,
                format!("remote socket not opened: {}", e),
            )
        })?;

        // send response header
        write_response_header(client_socket).await?;

        // forward data
        copy_bidirectional(client_socket, &mut remote_socket)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("forward data between client and remote failed: {}", e),
                )
            })?;

        Ok(())
    }

    async fn process_udp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        target: &str,
        port: u16,
    ) -> Result<()> {
        // check port (only support dns query)
        if port != 53 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "only DNS over HTTPS on port 53 is supported for UDP",
            ));
        }

        // send response header
        console_log!("udp outbound using doh target={} port={}", target, port);
        write_response_header(client_socket).await?;

        // forward data
        loop {
            // read packet length
            let length = client_socket.read_u16().await;
            if length.is_err() {
                return Ok(());
            }

            // read dns packet
            let packet = client_socket.read_bytes(length.unwrap() as usize).await?;

            // create request
            let request = Request::new_with_init("https://1.1.1.1/dns-query", &{
                // create request
                let mut init = RequestInit::new();
                init.method = Method::Post;
                init.headers = Headers::new();
                init.body = Some(packet.into());

                // set headers
                _ = init.headers.set("Content-Type", "application/dns-message");

                init
            })
            .unwrap();

            // invoke dns-over-http resolver
            let mut response = Fetch::Request(request).send().await.map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send DNS-over-HTTP request failed: {}", e),
                )
            })?;

            // read response
            let data = response.bytes().await.map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("DNS-over-HTTP response body error: {}", e),
                )
            })?;

            // write response
            client_socket.write_u16(data.len() as u16).await?;
            client_socket.write_all(&data).await?;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Command, VlessRequest, parse_early_data, parse_user_id, read_vless_request};
        use crate::protocol;
        use tokio_test::{block_on, io::Builder};

        fn sample_uuid() -> &'static str {
            "c55ba35f-12f6-436e-a451-4ce982c4ec1c"
        }

        #[test]
        fn parse_user_id_accepts_canonical_uuid() {
            let parsed = parse_user_id(sample_uuid()).expect("uuid should parse");
            assert_eq!(parsed.len(), 16);
        }

        #[test]
        fn parse_user_id_rejects_invalid_uuid() {
            let err = parse_user_id("not-a-uuid").expect_err("uuid must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }

        #[test]
        fn parse_early_data_decodes_websocket_payload() {
            let parsed = parse_early_data(Some("aGVsbG8".to_string()))
                .expect("early data should decode")
                .expect("payload should be present");
            assert_eq!(parsed, b"hello");
        }

        #[test]
        fn parse_vless_request_for_domain_tcp() {
            let user_id = parse_user_id(sample_uuid()).expect("uuid should parse");
            let frame = [
                vec![protocol::VERSION],
                user_id.to_vec(),
                vec![
                    0,
                    protocol::COMMAND_TCP,
                    0x01,
                    0xbb,
                    protocol::ADDRESS_TYPE_DOMAIN,
                    11,
                ],
                b"example.com".to_vec(),
            ]
            .concat();
            let mut reader = Builder::new().read(&frame).build();

            let request =
                block_on(read_vless_request(&mut reader, &user_id)).expect("request should parse");

            assert_eq!(
                request,
                VlessRequest {
                    command: Command::Tcp,
                    remote_port: 443,
                    remote_addr: "example.com".to_string(),
                }
            );
        }

        #[test]
        fn parse_vless_request_rejects_invalid_command() {
            let user_id = parse_user_id(sample_uuid()).expect("uuid should parse");
            let frame = [vec![protocol::VERSION], user_id.to_vec(), vec![0, 9]].concat();
            let mut reader = Builder::new().read(&frame).build();

            let err = block_on(read_vless_request(&mut reader, &user_id))
                .expect_err("command must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        }

        #[test]
        fn parse_vless_request_rejects_empty_domain() {
            let user_id = parse_user_id(sample_uuid()).expect("uuid should parse");
            let frame = [
                vec![protocol::VERSION],
                user_id.to_vec(),
                vec![
                    0,
                    protocol::COMMAND_TCP,
                    0x00,
                    0x50,
                    protocol::ADDRESS_TYPE_DOMAIN,
                    0,
                ],
            ]
            .concat();
            let mut reader = Builder::new().read(&frame).build();

            let err = block_on(read_vless_request(&mut reader, &user_id))
                .expect_err("empty domain must fail");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        }
    }
}

mod ext {
    use std::io::Result;
    use tokio::io::AsyncReadExt;
    #[allow(dead_code)]
    pub trait StreamExt {
        async fn read_string(&mut self, n: usize) -> Result<String>;
        async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>>;
    }

    impl<T: AsyncReadExt + Unpin + ?Sized> StreamExt for T {
        async fn read_string(&mut self, n: usize) -> Result<String> {
            self.read_bytes(n).await.map(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid string: {}", e),
                    )
                })
            })?
        }

        async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
            let mut buffer = vec![0u8; n];
            self.read_exact(&mut buffer).await?;

            Ok(buffer)
        }
    }
}

mod websocket {
    use futures_util::Stream;
    use std::{
        io::{Error, ErrorKind, Result},
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::{BufMut, BytesMut};
    use pin_project::pin_project;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use worker::{EventStream, WebSocket, WebsocketEvent};

    #[pin_project]
    pub struct WebSocketStream<'a> {
        ws: &'a WebSocket,
        #[pin]
        stream: EventStream<'a>,
        buffer: BytesMut,
    }

    impl<'a> WebSocketStream<'a> {
        pub fn new(
            ws: &'a WebSocket,
            stream: EventStream<'a>,
            early_data: Option<Vec<u8>>,
        ) -> Self {
            let mut buffer = BytesMut::new();
            if let Some(data) = early_data {
                buffer.put_slice(&data)
            }

            Self { ws, stream, buffer }
        }
    }

    impl AsyncRead for WebSocketStream<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            let mut this = self.project();

            loop {
                let amt = std::cmp::min(this.buffer.len(), buf.remaining());
                if amt > 0 {
                    buf.put_slice(&this.buffer.split_to(amt));
                    return Poll::Ready(Ok(()));
                }

                match this.stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                        if let Some(data) = msg.bytes() {
                            this.buffer.put_slice(&data);
                        };
                        continue;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
                    }
                    _ => return Poll::Ready(Ok(())), // None or Close event, return Ok to indicate stream end
                }
            }
        }
    }

    impl AsyncWrite for WebSocketStream<'_> {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            if let Err(e) = self.ws.send_with_bytes(buf) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            if let Err(e) = self.ws.close(None, Some("normal close")) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(()))
        }
    }
}
