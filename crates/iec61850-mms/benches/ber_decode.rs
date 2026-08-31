//! BER decode microbenchmark.
//!
//! Target: decoding a 100-byte PDU stays below 1 microsecond.
//!
//! Two fixtures:
//!   * `initiate_request` (about 50 bytes) is a real client-to-server handshake
//!     PDU, covering four CONTEXT tags nested in one SEQUENCE.
//!   * `confirmed_request_100b` (close to 100 bytes) wraps a ConfirmedRequest in
//!     the raw-bytes variant of `MmsPdu::decode`, measuring the hot path a server
//!     runs for every request: parse the outer tag and length, then extract the
//!     inner bytes.
//!
//! Run with:
//! ```sh
//! cargo bench -p iec61850-mms --bench ber_decode
//! ```

use bytes::BytesMut;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use iec61850_mms::mms::{InitiateRequestPdu, MmsPdu};

fn build_initiate_request_bytes() -> Vec<u8> {
    let pdu = MmsPdu::InitiateRequest(InitiateRequestPdu::default());
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);
    buf.to_vec()
}

fn build_confirmed_request_100b() -> Vec<u8> {
    // A raw-bytes ConfirmedRequest whose inner payload is 95 dummy bytes: the
    // benchmark measures only the outer tag and length parse plus the inner-byte
    // extraction, and never expands the service.
    let inner = vec![0xa5u8; 95];
    let pdu = MmsPdu::ConfirmedRequest(bytes::Bytes::from(inner));
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);
    buf.to_vec()
}

fn bench_decode(c: &mut Criterion) {
    let initiate = build_initiate_request_bytes();
    let confirmed = build_confirmed_request_100b();

    eprintln!(
        "[ber_decode] fixture sizes: initiate={}B, confirmed={}B",
        initiate.len(),
        confirmed.len()
    );

    let mut group = c.benchmark_group("ber_decode");
    group.throughput(Throughput::Elements(1));

    group.bench_function("initiate_request", |b| {
        b.iter(|| {
            let pdu = MmsPdu::decode(black_box(&initiate)).expect("decode initiate");
            black_box(pdu);
        });
    });

    group.bench_function("confirmed_request_100b", |b| {
        b.iter(|| {
            let pdu = MmsPdu::decode(black_box(&confirmed)).expect("decode confirmed");
            black_box(pdu);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
