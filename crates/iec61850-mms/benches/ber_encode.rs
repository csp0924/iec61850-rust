//! BER encode microbenchmark.
//!
//! Target: encoding a 100-byte PDU stays below 1 microsecond.
//!
//! The same two fixtures as the decode benchmark, measured on the encode path:
//!   * `initiate_request` is a real handshake encode, nested InitRequestDetail
//!     included.
//!   * `confirmed_request_100b` is the raw-bytes variant, measuring the outer tag
//!     and length write plus the payload copy.
//!
//! Run with:
//! ```sh
//! cargo bench -p iec61850-mms --bench ber_encode
//! ```

use bytes::BytesMut;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use iec61850_mms::mms::{InitiateRequestPdu, MmsPdu};

fn build_initiate_pdu() -> MmsPdu {
    MmsPdu::InitiateRequest(InitiateRequestPdu::default())
}

fn build_confirmed_pdu_100b() -> MmsPdu {
    let inner = vec![0xa5u8; 95];
    MmsPdu::ConfirmedRequest(bytes::Bytes::from(inner))
}

fn bench_encode(c: &mut Criterion) {
    let initiate = build_initiate_pdu();
    let confirmed = build_confirmed_pdu_100b();

    let mut probe = BytesMut::new();
    initiate.encode(&mut probe);
    let initiate_size = probe.len();
    probe.clear();
    confirmed.encode(&mut probe);
    let confirmed_size = probe.len();

    eprintln!(
        "[ber_encode] encoded sizes: initiate={}B, confirmed={}B",
        initiate_size, confirmed_size
    );

    let mut group = c.benchmark_group("ber_encode");
    group.throughput(Throughput::Elements(1));

    // One reusable BytesMut is cleared and refilled on every iteration, matching a
    // production transmit path, which reuses its buffer rather than allocating.
    group.bench_function("initiate_request", |b| {
        let mut buf = BytesMut::with_capacity(256);
        b.iter(|| {
            buf.clear();
            black_box(&initiate).encode(&mut buf);
            black_box(&buf);
        });
    });

    group.bench_function("confirmed_request_100b", |b| {
        let mut buf = BytesMut::with_capacity(256);
        b.iter(|| {
            buf.clear();
            black_box(&confirmed).encode(&mut buf);
            black_box(&buf);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
