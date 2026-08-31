//! `RcbWriteMask` and `TriggerOptions`.
//!
//! `RcbWriteMask` names the RCB fields a `set_rcb_values` call writes.
//! `TriggerOptions` is defined here, rather than shared with the server side,
//! because this crate does not depend on the server crate; the bit layout is
//! the same, bit 0 DATA_CHANGED through bit 4 GI.
//!
//! ConfRev, SqNum, Owner and TimeOfEntry are read-only. Their mask bits are
//! dropped inside `build_write_sequence`, and the removal is logged so that a
//! caller is not left believing the write took effect.

use bitflags::bitflags;

// TriggerOptions.

bitflags! {
    /// Trigger conditions of a report control block.
    ///
    /// Bit layout per IEC 61850-7-2: 0x01 DATA_CHANGED, 0x02 QUALITY_CHANGED,
    /// 0x04 DATA_UPDATE, 0x08 INTEGRITY, 0x10 GI.
    ///
    /// On the wire this is a BIT STRING(6) whose bit 0 is reserved and always
    /// zero, so semantic bit n is wire bit n + 1. The shift is applied by the
    /// codec in `handle.rs`; a caller works in semantic bits only.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct TriggerOptions: u8 {
        /// Triggered by a change of value.
        const DATA_CHANGED     = 0x01;
        /// Triggered by a change of quality.
        const QUALITY_CHANGED  = 0x02;
        /// Triggered by an update that does not change the value.
        const DATA_UPDATE      = 0x04;
        /// Triggered by the integrity period.
        const INTEGRITY        = 0x08;
        /// Triggered by a general interrogation.
        const GI               = 0x10;
    }
}

// RcbWriteMask

bitflags! {
    /// Selects which RCB fields `set_rcb_values` writes.
    ///
    /// Writable: RPT_ID, RPT_ENA, RESV, DAT_SET, OPT_FLDS, BUF_TM, TRG_OPS,
    /// INTG_PD, GI, PURGE_BUF, ENTRY_ID, RESV_TMS.
    ///
    /// Read-only, and dropped from a write mask with a warning: CONF_REV,
    /// SQ_NUM, ENTRY_TIME, OWNER.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct RcbWriteMask: u32 {
        /// RptId.
        const RPT_ID     = 0x0001;
        /// RptEna.
        const RPT_ENA    = 0x0002;
        /// Resv; unbuffered RCBs only, rejected for a BRCB.
        const RESV       = 0x0004;
        /// DatSet.
        const DAT_SET    = 0x0008;

        // Read-only fields, dropped from a write mask.

        /// ConfRev; read-only, ignored in a write.
        #[doc = "read-only, ignored in set"]
        const CONF_REV   = 0x0010;

        /// OptFlds.
        const OPT_FLDS   = 0x0020;
        /// BufTm, in milliseconds.
        const BUF_TM     = 0x0040;

        /// SqNum; read-only, ignored in a write.
        #[doc = "read-only, ignored in set"]
        const SQ_NUM     = 0x0080;

        /// TrgOps.
        const TRG_OPS    = 0x0100;
        /// IntgPd, in milliseconds.
        const INTG_PD    = 0x0200;
        /// GI, the general interrogation flag.
        const GI         = 0x0400;
        /// PurgeBuf; buffered RCBs only, rejected for a URCB.
        const PURGE_BUF  = 0x0800;
        /// EntryId; buffered RCBs only.
        const ENTRY_ID   = 0x1000;

        /// TimeOfEntry; read-only, ignored in a write.
        #[doc = "read-only, ignored in set"]
        const ENTRY_TIME = 0x2000;

        /// ResvTms; buffered RCBs only.
        const RESV_TMS   = 0x4000;

        /// Owner; read-only, ignored in a write.
        #[doc = "read-only, ignored in set"]
        const OWNER      = 0x8000;
    }
}

/// The read-only bits that `set_rcb_values` drops from a write mask:
/// CONF_REV, SQ_NUM, ENTRY_TIME and OWNER.
pub(crate) const READ_ONLY_MASK: RcbWriteMask = RcbWriteMask::from_bits_retain(
    RcbWriteMask::CONF_REV.bits()
        | RcbWriteMask::SQ_NUM.bits()
        | RcbWriteMask::ENTRY_TIME.bits()
        | RcbWriteMask::OWNER.bits(),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_mask_contains_correct_bits() {
        assert!(READ_ONLY_MASK.contains(RcbWriteMask::CONF_REV));
        assert!(READ_ONLY_MASK.contains(RcbWriteMask::SQ_NUM));
        assert!(READ_ONLY_MASK.contains(RcbWriteMask::ENTRY_TIME));
        assert!(READ_ONLY_MASK.contains(RcbWriteMask::OWNER));
        assert!(!READ_ONLY_MASK.contains(RcbWriteMask::RPT_ID));
        assert!(!READ_ONLY_MASK.contains(RcbWriteMask::RPT_ENA));
    }

    #[test]
    fn trigger_options_bits() {
        let all = TriggerOptions::DATA_CHANGED
            | TriggerOptions::QUALITY_CHANGED
            | TriggerOptions::DATA_UPDATE
            | TriggerOptions::INTEGRITY
            | TriggerOptions::GI;
        assert_eq!(all.bits(), 0x1f);
    }
}
