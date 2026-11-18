use hades::tds::packet::{read_prelogin, response_packet};
use hades::tds::prelogin::{response_payload, Prelogin};
use std::io::Cursor;

/// Public MS-TDS PRELOGIN request example, section 4.1.
const EXAMPLE: &[u8] = &[
    0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
    0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
    0x01, 0xff, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x01,
];

#[test]
fn parses_microsoft_prelogin_example() {
    let body = read_prelogin(&mut Cursor::new(EXAMPLE)).unwrap();
    let p = Prelogin::parse(&body).unwrap();
    assert_eq!(p.version, [9, 0, 0, 0, 0, 0]);
    assert_eq!(p.encryption, Some(1));
    assert_eq!(p.mars, Some(1));
    assert_eq!(p.instance_name, Some(vec![0]));
}

#[test]
fn response_is_structurally_valid() {
    let body = read_prelogin(&mut Cursor::new(EXAMPLE)).unwrap();
    let p = Prelogin::parse(&body).unwrap();
    let response_body = response_payload(&p);
    let frame = response_packet(&response_body).unwrap();
    assert_eq!(frame[0], 4);
    assert_eq!(frame[1], 1);
    assert_eq!(
        usize::from(u16::from_be_bytes([frame[2], frame[3]])),
        frame.len()
    );
    let response = Prelogin::parse(&frame[8..]).unwrap();
    assert_eq!(response.encryption, Some(2));
    assert_eq!(response.mars, Some(0));
}
