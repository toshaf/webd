use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

pub mod err;

#[cfg(test)]
mod tests;

pub struct Req {
    pub version: String,
    pub verb: Verb,
    pub path: String,
    pub headers: HashMap<String, String>,
}

impl Req {
    pub fn parse<T: BufRead>(mut client: T) -> err::Result<Req> {
        let mut buf = String::new();

        client.read_line(&mut buf)?;

        let mut req = buf.trim().split(' ');
        let verb = match req.next() {
            Some(v) => v,
            None => return err::input("no verb".to_string()),
        };
        let verb = match Verb::parse(verb) {
            Some(v) => v,
            None => return err::input(format!("unknown verb: {}", verb)),
        };
        let path = match req.next() {
            Some(v) => v.to_string(),
            None => return err::input("no path".to_string()),
        };
        let version = match req.next() {
            Some(v) => v.to_string(),
            None => return err::input("no version".to_string()),
        };

        while let Some(s) = req.next() {
            println!("unexpected bit: {}", s);
        }

        let mut headers = HashMap::new();
        let mut buf = String::new();
        loop {
            buf.clear();
            client.read_line(&mut buf)?;
            let hdr = buf.trim();
            if hdr.is_empty() {
                break;
            }
            let mut hdr = hdr.split(':');
            let name = match hdr.next() {
                Some(s) => s,
                None => continue,
            };
            let value = match hdr.next() {
                Some(s) => s,
                None => continue,
            };
            headers.insert(name.trim().to_string(), value.trim().to_string());
        }

        Ok(Req {
            version,
            verb: verb,
            path: path,
            headers,
        })
    }
}

pub enum Verb {
    Get,
}

impl Verb {
    pub fn parse(s: &str) -> Option<Verb> {
        match s {
            "GET" => Some(Verb::Get),
            _ => None,
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            Verb::Get => "GET",
        }
    }
}

impl std::fmt::Display for Verb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub enum Status {
    SwitchingProtocols,
    OK,
    BadRequest,
    NotFound,
    MethodNotAllowed,
}

impl Status {
    pub fn to_string(&self) -> &'static str {
        match self {
            Status::SwitchingProtocols => "101 Switching Protocols",
            Status::OK => "200 OK",
            Status::BadRequest => "400 Bad Request",
            Status::NotFound => "404 Not Found",
            Status::MethodNotAllowed => "405 Method Not Allowed",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub fn send_headers(
    client: &mut TcpStream,
    status: Status,
    content_type: &str,
    len: u64,
) -> err::Result<()> {
    println!(" => {}", status);
    write!(client, "HTTP/1.0 {}\n", status)?;
    write!(client, "Server: webd 0.1\n")?;
    write!(client, "Content-Type: {}\n", content_type)?;
    write!(client, "Content-Length: {}\n", len)?;
    write!(client, "\n")?;

    Ok(())
}

pub fn send_str(
    mut client: TcpStream,
    status: Status,
    content_type: &str,
    content: &str,
) -> err::Result<()> {
    send_headers(&mut client, status, content_type, content.len() as u64)?;

    write!(client, "{}", content)?;

    Ok(())
}

pub fn send_file(
    mut client: TcpStream,
    status: Status,
    content_type: &str,
    fname: &str,
) -> err::Result<()> {
    let len = std::fs::metadata(fname)?.len();
    send_headers(&mut client, status, content_type, len)?;

    let mut file = std::fs::File::open(fname)?;
    std::io::copy(&mut file, &mut client)?;

    Ok(())
}

pub type App = fn(Req, TcpStream) -> err::Result<()>;

pub fn serve(endpoint: &str, app: App) -> err::Result<()> {
    let server = TcpListener::bind(endpoint)?;
    println!("bound to {}", endpoint);

    for client in server.incoming() {
        let mut stream = BufReader::new(client?);
        let req = match Req::parse(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                println!("problem with request: {}", e);
                match e {
                    err::Error::Input(mut msg) => {
                        msg.push('\n');
                        let r = send_str(
                            stream.into_inner(),
                            Status::BadRequest,
                            "text/plain",
                            msg.as_str(),
                        );
                        match r {
                            Err(e) => println!("problem sending: {}", e),
                            Ok(_) => {}
                        }
                        continue;
                    }
                    _ => {}
                }
                continue;
            }
        };

        println!("{} {} {}", req.version, req.verb, req.path);

        app(req, stream.into_inner())?;
    }

    Ok(())
}

enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl OpCode {
    fn parse(val: u8) -> Option<OpCode> {
        let opc = val & 0xf;
        match opc {
            0x0 => Some(OpCode::Continuation),
            0x1 => Some(OpCode::Text),
            0x2 => Some(OpCode::Binary),
            0x8 => Some(OpCode::Close),
            0x9 => Some(OpCode::Ping),
            0xA => Some(OpCode::Pong),
            _ => None,
        }
    }

    fn as_byte(&self) -> u8 {
        match self {
            OpCode::Continuation => 0x0,
            OpCode::Text => 0x1,
            OpCode::Binary => 0x2,
            OpCode::Close => 0x8,
            OpCode::Ping => 0x9,
            OpCode::Pong => 0xA,
        }
    }
}

struct FrameHeader {
    fin: bool,
    opcode: OpCode,
    header_len: usize,
    payload_len: usize,
    masking_key: Option<[u8; 4]>,
}

impl FrameHeader {
    pub fn frame_len(&self) -> usize {
        self.header_len + self.payload_len
    }

    pub fn parse(buf: &[u8]) -> Option<FrameHeader> {
        let n = buf.len();
        let mut used = 2;
        if n > 1 {
            let fin = (buf[0] & 0x80) == 0x80;
            let opcode = buf[0] & 0x0f;
            if let Some(opcode) = OpCode::parse(opcode) {
                let mask = (buf[1] & 0x80) == 0x80;
                let mut payload_len = (buf[1] & 0x7f) as usize;
                match payload_len {
                    126 => {
                        if n < 4 {
                            return None;
                        }
                        payload_len = ((buf[2] as usize) << 8) | buf[3] as usize;
                        used += 2;
                    }
                    127 => {
                        if n < 10 {
                            return None;
                        }
                        payload_len = ((buf[2] as usize) << 7 * 8)
                            | ((buf[3] as usize) << 6 * 8)
                            | ((buf[4] as usize) << 5 * 8)
                            | ((buf[5] as usize) << 4 * 8)
                            | ((buf[6] as usize) << 3 * 8)
                            | ((buf[7] as usize) << 2 * 8)
                            | ((buf[8] as usize) << 8)
                            | buf[9] as usize;
                        used += 8;
                    }
                    _ => {}
                }
                let masking_key = if mask {
                    let mut key = [0u8; 4];
                    key.clone_from_slice(&buf[used..used + 4]);
                    used += 4;
                    Some(key)
                } else {
                    None
                };
                Some(FrameHeader {
                    fin,
                    opcode,
                    header_len: used,
                    payload_len,
                    masking_key,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    fn unmask(&self, buf: &[u8]) -> Vec<u8> {
        let mut vs = buf.to_vec();
        match self.masking_key {
            Some(key) => {
                for i in 0..vs.len() {
                    vs[i] ^= key[i % 4];
                }
                vs
            }
            None => vs,
        }
    }

    fn write(&self, out: &mut impl Write) -> err::Result<usize> {
        let mut buf = Vec::with_capacity(self.frame_len());

        let b = match self.fin {
            false => 0u8,
            true => 0x80,
        };
        let b = b | self.opcode.as_byte();
        buf.push(b);

        let b = match self.masking_key.is_some() {
            false => 0u8,
            true => 0x80,
        };

        if self.payload_len > u16::MAX as usize {
            buf.push(b | 127);
            buf.push((self.payload_len >> 7 * 8) as u8);
            buf.push((self.payload_len >> 6 * 8) as u8);
            buf.push((self.payload_len >> 5 * 8) as u8);
            buf.push((self.payload_len >> 4 * 8) as u8);
            buf.push((self.payload_len >> 3 * 8) as u8);
            buf.push((self.payload_len >> 2 * 8) as u8);
            buf.push((self.payload_len >> 1 * 8) as u8);
            buf.push(self.payload_len as u8);
        } else if self.payload_len > 125 {
            buf.push(b | 126);
            buf.push((self.payload_len >> 1 * 8) as u8);
            buf.push(self.payload_len as u8);
        } else {
            buf.push(b | (self.payload_len as u8));
        }

        match self.masking_key {
            None => {}
            Some(arr) => {
                buf.push(arr[0]);
                buf.push(arr[1]);
                buf.push(arr[2]);
                buf.push(arr[3]);
            }
        }

        Ok(out.write(&buf[..])?)
    }

    pub fn final_text(payload_len: usize, masking_key: Option<[u8; 4]>) -> FrameHeader {
        let header_fixed = 1;

        let payload_extra = if payload_len > u16::MAX as usize {
            8
        } else if payload_len > 125 {
            2
        } else {
            0
        };

        let mask_len = match masking_key {
            None => 0,
            Some(arr) => arr.len(),
        };

        let header_len = header_fixed + payload_extra + mask_len;

        FrameHeader {
            fin: true,
            opcode: OpCode::Text,
            header_len,
            payload_len,
            masking_key,
        }
    }
}

#[derive(Debug)]
pub enum Payload {
    Str(String),
    Bin(Vec<u8>),
}

pub struct WebSocket {
    req: Req,
    client: BufReader<TcpStream>,
    open: bool,
}

impl WebSocket {
    fn new(req: Req, client: BufReader<TcpStream>) -> WebSocket {
        WebSocket {
            req,
            client,
            open: true,
        }
    }

    pub fn recv(&mut self) -> err::Result<Option<Payload>> {
        if !self.open {
            return Ok(None);
        }

        println!("recv from {}", self.req.path);

        let buf = self.client.fill_buf()?;
        let hdr = match FrameHeader::parse(buf) {
            Some(h) => h,
            None => return Ok(None),
        };

        if buf.len() < hdr.frame_len() {
            return Ok(None);
        }

        if !hdr.fin {
            todo!("continuations");
        }

        let result = match hdr.opcode {
            OpCode::Continuation => {
                todo!("got a continuation");
            }
            OpCode::Text => {
                let s = String::from_utf8(hdr.unmask(&buf[hdr.header_len..]))?;
                Ok(Some(Payload::Str(s)))
            }
            OpCode::Binary => Ok(Some(Payload::Bin(hdr.unmask(&buf[hdr.header_len..])))),
            OpCode::Close => {
                self.open = false;
                Ok(None)
            }
            OpCode::Ping => {
                todo!("send pong");
            }
            OpCode::Pong => {
                todo!("nothing?");
            }
        };

        self.client.consume(hdr.frame_len());

        result
    }

    pub fn send_str(&mut self, msg: &str) -> err::Result<usize> {
        let payload = msg.as_bytes();
        let hdr = FrameHeader::final_text(payload.len(), None);

        let out = self.client.get_mut();
        let mut num = hdr.write(out)?;
        num += out.write(payload)?;
        Ok(num)
    }
}

pub enum WsUpgrade {
    Success(WebSocket),
    Failure((Req, TcpStream)),
    Error(err::Error),
}

impl From<std::io::Error> for WsUpgrade {
    fn from(e: std::io::Error) -> Self {
        WsUpgrade::Error(e.into())
    }
}

pub fn ws_upgrade(req: Req, mut client: TcpStream) -> WsUpgrade {
    match req.headers.get("Connection") {
        Some(s) => match s.as_str() {
            "Upgrade" => {}
            _ => return WsUpgrade::Failure((req, client)),
        },
        None => return WsUpgrade::Failure((req, client)),
    }

    match req.headers.get("Upgrade") {
        Some(s) => match s.as_str() {
            "websocket" => {}
            _ => return WsUpgrade::Failure((req, client)),
        },
        None => return WsUpgrade::Failure((req, client)),
    }

    let mut key = match req.headers.get("Sec-WebSocket-Key") {
        Some(s) => s.to_string(),
        None => {
            return WsUpgrade::Error(err::Error::Input("missing Sec-WebSocket-Key".to_string()))
        }
    };

    key.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    let hash = hash.finalize();
    let accept = b64.encode(hash);

    match write_ws_headers(&mut client, &accept) {
        Ok(_) => {}
        Err(e) => return WsUpgrade::Error(e),
    }

    WsUpgrade::Success(WebSocket::new(req, BufReader::new(client)))
}

fn write_ws_headers(client: &mut TcpStream, accept: &str) -> err::Result<()> {
    write!(client, "HTTP/1.0 {}\n", Status::SwitchingProtocols)?;
    write!(client, "Server: webd 0.1\n")?;
    write!(client, "Connection: upgrade\n")?;
    write!(client, "Upgrade: websocket\n")?;
    write!(client, "Sec-WebSocket-Accept: {}\n", accept)?;
    write!(client, "\n")?;

    Ok(())
}
