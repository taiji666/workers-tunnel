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
    use std::collections::HashMap;
    use std::io::{Error, ErrorKind, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::ext::StreamExt;
    use crate::protocol;
    use crate::websocket::WebSocketStream;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures_channel::mpsc;
    use futures_util::StreamExt as FuturesStreamExt;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
        copy_bidirectional, split,
    };
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
        target: Option<TargetAddress>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TargetAddress {
        remote_port: u16,
        remote_addr: String,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MuxSessionStatus {
        New = 0x01,
        Keep = 0x02,
        End = 0x03,
        KeepAlive = 0x04,
    }

    impl TryFrom<u8> for MuxSessionStatus {
        type Error = Error;

        fn try_from(value: u8) -> Result<Self> {
            match value {
                0x01 => Ok(Self::New),
                0x02 => Ok(Self::Keep),
                0x03 => Ok(Self::End),
                0x04 => Ok(Self::KeepAlive),
                _ => Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid mux session status: {}", value),
                )),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MuxNetwork {
        Tcp = 0x01,
        Udp = 0x02,
    }

    impl TryFrom<u8> for MuxNetwork {
        type Error = Error;

        fn try_from(value: u8) -> Result<Self> {
            match value {
                0x01 => Ok(Self::Tcp),
                0x02 => Ok(Self::Udp),
                _ => Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid mux network: {}", value),
                )),
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct MuxFrame {
        session_id: u16,
        status: MuxSessionStatus,
        has_data: bool,
        has_error: bool,
        target: Option<(MuxNetwork, TargetAddress)>,
        data: Vec<u8>,
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
        let target = match command {
            Command::Tcp | Command::Udp => Some(TargetAddress {
                remote_port: reader.read_u16().await?,
                remote_addr: read_remote_address(reader).await?,
            }),
            Command::Mux => None,
        };

        Ok(VlessRequest { command, target })
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

    async fn read_mux_frame<R>(reader: &mut R) -> Result<MuxFrame>
    where
        R: AsyncRead + Unpin,
    {
        let metadata_len = reader.read_u16().await?;
        if !(4..=512).contains(&metadata_len) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("invalid mux metadata length: {}", metadata_len),
            ));
        }

        let metadata = reader.read_bytes(metadata_len as usize).await?;
        let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
        let status = MuxSessionStatus::try_from(metadata[2])?;
        let options = metadata[3];
        let has_data = options & 0x01 != 0;
        let has_error = options & 0x02 != 0;

        let target = if status == MuxSessionStatus::New {
            let mut metadata_reader = &metadata[4..];
            let network = MuxNetwork::try_from(metadata_reader.read_u8().await?)?;
            let remote_port = metadata_reader.read_u16().await?;
            let remote_addr = read_remote_address(&mut metadata_reader).await?;
            Some((
                network,
                TargetAddress {
                    remote_port,
                    remote_addr,
                },
            ))
        } else {
            None
        };

        let data = if has_data {
            let data_len = reader.read_u16().await?;
            reader.read_bytes(data_len as usize).await?
        } else {
            Vec::new()
        };

        Ok(MuxFrame {
            session_id,
            status,
            has_data,
            has_error,
            target,
            data,
        })
    }

    fn encode_target_address(target: &TargetAddress) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&target.remote_port.to_be_bytes());

        if let Ok(addr) = target.remote_addr.parse::<Ipv4Addr>() {
            encoded.push(protocol::ADDRESS_TYPE_IPV4);
            encoded.extend_from_slice(&addr.octets());
            return Ok(encoded);
        }

        if let Some(stripped) = target
            .remote_addr
            .strip_prefix('[')
            .and_then(|addr| addr.strip_suffix(']'))
        {
            let addr = stripped.parse::<Ipv6Addr>().map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid ipv6 address: {}", err),
                )
            })?;
            encoded.push(protocol::ADDRESS_TYPE_IPV6);
            encoded.extend_from_slice(&addr.octets());
            return Ok(encoded);
        }

        if target.remote_addr.is_empty() || target.remote_addr.len() > u8::MAX as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "domain address must be 1..=255 bytes",
            ));
        }

        encoded.push(protocol::ADDRESS_TYPE_DOMAIN);
        encoded.push(target.remote_addr.len() as u8);
        encoded.extend_from_slice(target.remote_addr.as_bytes());
        Ok(encoded)
    }

    fn encode_mux_frame(
        session_id: u16,
        status: MuxSessionStatus,
        has_error: bool,
        target: Option<(MuxNetwork, &TargetAddress)>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&session_id.to_be_bytes());
        metadata.push(status as u8);
        let mut options = 0u8;
        if !data.is_empty() {
            options |= 0x01;
        }
        if has_error {
            options |= 0x02;
        }
        metadata.push(options);

        if status == MuxSessionStatus::New {
            let (network, target) = target.ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "mux new frame requires target metadata",
                )
            })?;
            metadata.push(network as u8);
            metadata.extend_from_slice(&encode_target_address(target)?);
        }

        let mut frame = Vec::new();
        frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        frame.extend_from_slice(&metadata);
        if !data.is_empty() {
            if data.len() > u16::MAX as usize {
                return Err(Error::new(ErrorKind::InvalidInput, "mux payload too large"));
            }
            frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
            frame.extend_from_slice(data);
        }
        Ok(frame)
    }

    fn send_mux_frame(
        tx: &mpsc::UnboundedSender<Vec<u8>>,
        session_id: u16,
        status: MuxSessionStatus,
        has_error: bool,
        target: Option<(MuxNetwork, &TargetAddress)>,
        data: &[u8],
    ) -> Result<()> {
        tx.unbounded_send(encode_mux_frame(
            session_id, status, has_error, target, data,
        )?)
        .map_err(|_| Error::new(ErrorKind::BrokenPipe, "mux writer channel closed"))
    }

    async fn connect_tcp_socket(target: &str, port: u16) -> Result<Socket> {
        let remote_socket = Socket::builder().connect(target, port).map_err(|e| {
            Error::new(
                ErrorKind::ConnectionAborted,
                format!("connect to remote failed: {}", e),
            )
        })?;

        remote_socket.opened().await.map_err(|e| {
            Error::new(
                ErrorKind::ConnectionReset,
                format!("remote socket not opened: {}", e),
            )
        })?;

        Ok(remote_socket)
    }

    async fn connect_tcp_socket_with_fallback(
        target: &TargetAddress,
        proxy_ip: &[String],
    ) -> Result<(Socket, String)> {
        for candidate in [vec![target.remote_addr.clone()], proxy_ip.to_vec()].concat() {
            match connect_tcp_socket(&candidate, target.remote_port).await {
                Ok(socket) => return Ok((socket, candidate)),
                Err(err) if err.kind() == ErrorKind::ConnectionReset => continue,
                Err(err) => return Err(err),
            }
        }

        Err(Error::new(ErrorKind::InvalidData, "no target to connect"))
    }

    pub async fn run_tunnel(
        mut client_socket: WebSocketStream<'_>,
        user_id: UserId,
        proxy_ip: Vec<String>,
    ) -> Result<()> {
        let request = read_vless_request(&mut client_socket, &user_id).await?;

        console_log!(
            "tunnel request parsed: command={:?}, target={:?}, fallback_targets={}",
            request.command,
            request.target,
            if proxy_ip.is_empty() {
                "<none>".to_string()
            } else {
                proxy_ip.join(",")
            }
        );

        // process outbound
        match request.command {
            Command::Tcp => {
                let target = request.target.ok_or_else(|| {
                    Error::new(ErrorKind::InvalidData, "tcp request missing target")
                })?;
                // try to connect to remote
                for outbound_target in [vec![target.remote_addr.clone()], proxy_ip].concat() {
                    console_log!(
                        "tcp outbound attempt: target={}, port={}",
                        outbound_target,
                        target.remote_port
                    );
                    match process_tcp_outbound(
                        &mut client_socket,
                        &outbound_target,
                        target.remote_port,
                    )
                    .await
                    {
                        Ok(_) => {
                            console_log!(
                                "tcp outbound connected: target={}, port={}",
                                outbound_target,
                                target.remote_port
                            );
                            // normal closed
                            return Ok(());
                        }
                        Err(e) => {
                            console_error!(
                                "tcp outbound failed: target={}, port={}, kind={:?}, error={}",
                                outbound_target,
                                target.remote_port,
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
                    target.remote_port
                );
                Err(Error::new(ErrorKind::InvalidData, "no target to connect"))
            }
            Command::Udp => {
                let target = request.target.ok_or_else(|| {
                    Error::new(ErrorKind::InvalidData, "udp request missing target")
                })?;
                console_log!(
                    "udp outbound request: remote_addr={}, remote_port={}",
                    target.remote_addr,
                    target.remote_port
                );
                process_udp_outbound(&mut client_socket, &target.remote_addr, target.remote_port)
                    .await
            }
            Command::Mux => process_mux_outbound(client_socket, proxy_ip).await,
        }
    }

    async fn process_mux_outbound(
        mut client_socket: WebSocketStream<'_>,
        proxy_ip: Vec<String>,
    ) -> Result<()> {
        let ws = client_socket.websocket();
        let (tx, mut rx) = mpsc::unbounded::<Vec<u8>>();
        let writer_ws = ws.clone();
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(frame) = FuturesStreamExt::next(&mut rx).await {
                if let Err(err) = writer_ws.send_with_bytes(frame) {
                    console_error!("mux writer send failed: {}", err);
                    break;
                }
            }
        });

        write_response_header(&mut client_socket).await?;

        let mut sessions: HashMap<u16, WriteHalf<Socket>> = HashMap::new();
        loop {
            let frame = match read_mux_frame(&mut client_socket).await {
                Ok(frame) => frame,
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            };

            match frame.status {
                MuxSessionStatus::KeepAlive => {}
                MuxSessionStatus::End => {
                    sessions.remove(&frame.session_id);
                }
                MuxSessionStatus::New => {
                    let (network, target) = frame.target.ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "mux new frame missing target")
                    })?;
                    if network != MuxNetwork::Tcp {
                        send_mux_frame(
                            &tx,
                            frame.session_id,
                            MuxSessionStatus::End,
                            true,
                            None,
                            &[],
                        )?;
                        continue;
                    }

                    let (socket, connected_target) = match connect_tcp_socket_with_fallback(
                        &target, &proxy_ip,
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            console_error!(
                                "mux tcp outbound failed: session_id={}, target={}, port={}, error={}",
                                frame.session_id,
                                target.remote_addr,
                                target.remote_port,
                                err
                            );
                            send_mux_frame(
                                &tx,
                                frame.session_id,
                                MuxSessionStatus::End,
                                true,
                                None,
                                &[],
                            )?;
                            continue;
                        }
                    };

                    console_log!(
                        "mux tcp outbound connected: session_id={}, target={}, port={}",
                        frame.session_id,
                        connected_target,
                        target.remote_port
                    );

                    let (mut read_half, mut write_half) = split(socket);
                    if !frame.data.is_empty() {
                        write_half.write_all(&frame.data).await?;
                    }
                    sessions.insert(frame.session_id, write_half);

                    let session_id = frame.session_id;
                    let tx_clone = tx.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Err(err) =
                            pump_mux_downlink(session_id, &mut read_half, tx_clone).await
                        {
                            console_error!(
                                "mux downlink failed for session {}: {}",
                                session_id,
                                err
                            );
                        }
                    });
                }
                MuxSessionStatus::Keep => {
                    let Some(writer) = sessions.get_mut(&frame.session_id) else {
                        send_mux_frame(
                            &tx,
                            frame.session_id,
                            MuxSessionStatus::End,
                            true,
                            None,
                            &[],
                        )?;
                        continue;
                    };

                    if !frame.data.is_empty() {
                        if let Err(err) = writer.write_all(&frame.data).await {
                            console_error!(
                                "mux uplink write failed: session_id={}, error={}",
                                frame.session_id,
                                err
                            );
                            sessions.remove(&frame.session_id);
                            send_mux_frame(
                                &tx,
                                frame.session_id,
                                MuxSessionStatus::End,
                                true,
                                None,
                                &[],
                            )?;
                        }
                    }
                }
            }
        }
    }

    async fn pump_mux_downlink(
        session_id: u16,
        read_half: &mut ReadHalf<Socket>,
        tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 8192];
        loop {
            let read = read_half.read(&mut buffer).await?;
            if read == 0 {
                send_mux_frame(&tx, session_id, MuxSessionStatus::End, false, None, &[])?;
                return Ok(());
            }

            send_mux_frame(
                &tx,
                session_id,
                MuxSessionStatus::Keep,
                false,
                None,
                &buffer[..read],
            )?;
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
        use super::{
            Command, MuxNetwork, MuxSessionStatus, TargetAddress, VlessRequest, parse_early_data,
            parse_user_id, read_mux_frame, read_vless_request,
        };
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
                    target: Some(TargetAddress {
                        remote_port: 443,
                        remote_addr: "example.com".to_string(),
                    }),
                }
            );
        }

        #[test]
        fn parse_vless_request_for_mux_stops_after_command() {
            let user_id = parse_user_id(sample_uuid()).expect("uuid should parse");
            let frame = [
                vec![protocol::VERSION],
                user_id.to_vec(),
                vec![0, protocol::COMMAND_MUX],
            ]
            .concat();
            let mut reader = Builder::new().read(&frame).build();

            let request =
                block_on(read_vless_request(&mut reader, &user_id)).expect("request should parse");

            assert_eq!(
                request,
                VlessRequest {
                    command: Command::Mux,
                    target: None,
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

        #[test]
        fn parse_mux_frame_for_tcp_session() {
            let frame = [
                vec![0x00, 0x14],
                vec![
                    0x00,
                    0x01,
                    MuxSessionStatus::New as u8,
                    0x01,
                    MuxNetwork::Tcp as u8,
                    0x01,
                    0xbb,
                    protocol::ADDRESS_TYPE_DOMAIN,
                    11,
                ],
                b"example.com".to_vec(),
                vec![0x00, 0x05],
                b"hello".to_vec(),
            ]
            .concat();
            let mut reader = Builder::new().read(&frame).build();

            let parsed = block_on(read_mux_frame(&mut reader)).expect("mux frame should parse");

            assert_eq!(parsed.session_id, 1);
            assert_eq!(parsed.status, MuxSessionStatus::New);
            assert!(parsed.has_data);
            assert_eq!(parsed.data, b"hello");
            assert_eq!(
                parsed.target,
                Some((
                    MuxNetwork::Tcp,
                    TargetAddress {
                        remote_port: 443,
                        remote_addr: "example.com".to_string(),
                    },
                ))
            );
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

        pub fn websocket(&self) -> WebSocket {
            self.ws.clone()
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
