//! smpCnt continuity accounting of `SvSubscriber`.

use iec61850_sv::pdu::{Asdu, SmpMod, SmpSynch};
use iec61850_sv::subscriber::{SvSubscriber, SvSubscriberAsdu, SvSubscriberBuilder};

mod log_capture;
use log_capture::warnings_containing;

fn asdu(sv_id: &str, cnt: u16) -> Asdu {
    Asdu {
        sv_id: sv_id.into(),
        dat_set: None,
        smp_cnt: cnt,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: SmpSynch::GlobalClock,
        smp_rate: None,
        sample: vec![0; 64],
        smp_mod: None,
        gm_identity: None,
    }
}

fn feed(sub: &SvSubscriber, asdus: impl IntoIterator<Item = Asdu>) {
    for a in asdus {
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&a));
    }
}

fn counts(sub: &SvSubscriber, cnts: impl IntoIterator<Item = u16>) {
    feed(sub, cnts.into_iter().map(|c| asdu("MU01", c)));
}

#[test]
fn rollover_once_a_second_without_a_limit_is_not_a_gap() {
    let sub = SvSubscriber::builder().sv_id("MU01").build();
    counts(&sub, (3990..4000).chain(0..10));
    assert_eq!(sub.missed_count(), 0);
}

#[test]
fn rollover_at_the_configured_limit_is_not_a_gap() {
    let sub = SvSubscriberBuilder::new()
        .sv_id("MU01")
        .smp_cnt_limit(4000)
        .build();
    counts(&sub, (3990..4000).chain(0..10));
    assert_eq!(sub.missed_count(), 0);
}

#[test]
fn samples_lost_across_the_configured_limit_are_counted() {
    let sub = SvSubscriberBuilder::new()
        .sv_id("MU01")
        .smp_cnt_limit(4000)
        .build();
    // 3996..=3999, 0 and 1 are missing.
    counts(&sub, [3994, 3995, 2, 3]);
    assert_eq!(sub.missed_count(), 6);
}

#[test]
fn samples_lost_across_an_announced_rate_are_counted() {
    let sub = SvSubscriber::builder().sv_id("MU01").build();
    let announced = |c| Asdu {
        smp_rate: Some(4000),
        smp_mod: Some(SmpMod::SamplesPerSecond),
        ..asdu("MU01", c)
    };
    feed(&sub, [3990, 3999, 0, 2].map(announced));
    assert_eq!(sub.missed_count(), 8 + 1);
}

#[test]
fn counter_wrap_at_65536_is_not_a_gap() {
    let sub = SvSubscriber::builder().sv_id("MU01").build();
    counts(&sub, [65534, 65535, 0, 1]);
    assert_eq!(sub.missed_count(), 0);
}

#[test]
fn ordinary_gap_is_counted() {
    let sub = SvSubscriberBuilder::new()
        .sv_id("MU01")
        .smp_cnt_limit(4000)
        .build();
    counts(&sub, [10, 11, 15]);
    assert_eq!(sub.missed_count(), 3);
}

#[test]
fn interleaved_streams_keep_their_own_continuity() {
    let sub = SvSubscriber::builder().build();
    for c in 100..110 {
        feed(&sub, [asdu("MU01", c), asdu("MU02", c + 2000)]);
    }
    assert_eq!(sub.missed_count(), 0);
}

#[test]
fn gap_in_one_of_interleaved_streams_is_counted() {
    let sub = SvSubscriber::builder().build();
    feed(
        &sub,
        [
            asdu("MU01", 1),
            asdu("MU02", 50),
            asdu("MU01", 2),
            asdu("MU02", 53),
            asdu("MU01", 3),
        ],
    );
    assert_eq!(sub.missed_count(), 2);
}

#[test]
fn least_recent_stream_is_forgotten_when_full() {
    let sub = SvSubscriber::builder().max_streams(2).build();
    feed(
        &sub,
        [
            asdu("MU01", 1),
            asdu("MU02", 1),
            asdu("MU03", 1),
            // MU01 was forgotten and starts a new baseline; MU03 is followed.
            asdu("MU01", 500),
            asdu("MU03", 2),
        ],
    );
    assert_eq!(sub.missed_count(), 0);
}

#[test]
fn lost_reset_sample_without_a_limit_counts_only_the_samples_after_zero() {
    let sub = SvSubscriber::builder().sv_id("MU01").build();
    // Sample 0 of the next second is missing.
    counts(&sub, (3990..4000).chain(1..10));
    assert_eq!(sub.missed_count(), 1);
}

#[test]
fn smp_rate_without_smp_mod_is_not_a_limit() {
    let sub = SvSubscriber::builder().sv_id("MU01").build();
    // smpMod absent means samples per nominal period, so 80 is no wrap point.
    let per_period = |c| Asdu {
        smp_rate: Some(80),
        ..asdu("MU01", c)
    };
    feed(&sub, (3990..4000).chain(0..10).map(per_period));
    assert_eq!(sub.missed_count(), 0);
}

#[test]
fn limit_of_zero_is_ignored() {
    let sub = SvSubscriberBuilder::new()
        .sv_id("MU01")
        .smp_cnt_limit(0)
        .build();
    counts(&sub, (3990..4000).chain(0..10));
    assert_eq!(sub.missed_count(), 0);
}

#[test]
fn counter_beyond_the_limit_falls_back_to_plain_counting() {
    let sub = SvSubscriberBuilder::new()
        .sv_id("MU01")
        .smp_cnt_limit(4000)
        .build();
    counts(&sub, [5000, 5001, 5003]);
    assert_eq!(sub.missed_count(), 1);
}

#[test]
fn least_recently_heard_stream_is_forgotten_rather_than_the_oldest() {
    let sub = SvSubscriber::builder().max_streams(2).build();
    feed(
        &sub,
        [
            asdu("MU01", 1),
            asdu("MU02", 1),
            asdu("MU01", 2),
            // MU02 is the least recently heard and makes room for MU03.
            asdu("MU03", 1),
            // MU01 is still followed, so the skipped 3 and 4 count.
            asdu("MU01", 5),
        ],
    );
    assert_eq!(sub.missed_count(), 2);
}

#[test]
fn evictions_are_logged_once() {
    let sub = SvSubscriber::builder().max_streams(1).build();
    let logged = warnings_containing("forgetting svid", || {
        for c in 0..20u16 {
            feed(&sub, [asdu(&format!("MU{:02}", c % 5), c)]);
        }
    });
    assert_eq!(logged, 1);
}
