use crate::err;
use std::io::BufReader;

#[test]
fn parse_req() -> err::Result<()> {
    let mut raw = String::new();
    raw.push_str("GET /api/map HTTP/1.1\n");
    raw.push_str("Host: example.com\n");
    raw.push_str("Accept: */*\n");
    raw.push_str("\n");

    let req = crate::Req::parse(BufReader::new(raw.as_bytes()))?;
    assert_eq!(req.path.as_str(), "/api/map");

    Ok(())
}
