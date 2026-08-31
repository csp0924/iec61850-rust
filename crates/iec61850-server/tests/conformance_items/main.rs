//! Conformance tests against the IEC 61850-10 abstract test items.
//!
//! `catalog.rs` is the coverage table: it lists every abstract test item of
//! IEC 61850-10, with the clause and table it comes from and the check it
//! prescribes. It is a reference list, not a set of tests.
//!
//! An item counts as implemented when a test function in the `s_srv` module
//! here exercises it; that function is named after the item, lowercased with
//! underscores (`sSrv1` becomes `s_srv1`). Items with no test function are not
//! covered by this binary. To count the covered ones, run
//! `cargo test -p iec61850-server --test conformance_items -- --list`; its
//! total counts the two catalog meta-tests below as well, so subtract two.
//! The number of items in the table is `catalog::TOTAL_ITEMS`.
//!
//! Run with `cargo test -p iec61850-server --test conformance_items`.

#![allow(non_snake_case, dead_code)]

mod catalog;
mod s_srv;

use catalog::{ITEMS, TOTAL_ITEMS};

#[test]
fn catalog_row_count_matches_total_items() {
    assert_eq!(
        ITEMS.len(),
        TOTAL_ITEMS,
        "ITEMS length does not match TOTAL_ITEMS"
    );
}

#[test]
fn every_catalog_item_has_a_description() {
    for (id, _sec, desc) in ITEMS {
        assert!(!desc.trim().is_empty(), "{id} has an empty description");
    }
}
