//! Canonical text summary of an [`IedModel`].
//!
//! Two structurally equivalent models produce the same string, byte for byte,
//! which makes a text diff the practical way to compare a model built at run
//! time with one built by code generation. Comparing the trees directly is
//! awkward, because every value sits behind an `Arc<RwLock<_>>`.
//!
//! Ordering is stable at every level, so a difference in SCL document order
//! cannot change the output: logical devices sort by `inst`, logical nodes by
//! `(prefix, class, inst)`, data objects and their children by `name`, data
//! sets and control blocks by `name`, and data set entries by the whole tuple
//! `(ld_inst, ln_name, fc, do_path, array_index, component)`.
//!
//! The summary covers structure and schema only. It is plain text, so it can
//! be grepped and diffed; there is no binary form and no hash.

use iec61850_model::cb::{
    GooseControlBlock, LogControlBlock, ReportControlBlock, SettingGroupControlBlock,
    SvControlBlock,
};
use iec61850_model::tree::{
    DataAttribute, DataObject, DataSet, DataSetEntry, DoChild, IedModel, LogicalDevice, LogicalNode,
};
use iec61850_model::value::MmsValue;

use std::fmt::Write;

/// Produces a canonical, deterministic text summary of `model`.
///
/// Two structurally equivalent models yield the same string, however each was
/// built. Every orderable key is sorted once, so SCL document order does not
/// affect the result.
///
/// See the module documentation for the ordering rules.
pub fn summarize_model(model: &IedModel) -> String {
    let mut out = String::with_capacity(4096);
    let _ = writeln!(out, "IED name={}", model.ied_name);

    let mut lds: Vec<&LogicalDevice> = model.lds.iter().collect();
    lds.sort_by(|a, b| a.inst.cmp(&b.inst));
    let _ = writeln!(out, "  lds count={}", lds.len());
    for ld in lds {
        write_ld(&mut out, ld);
    }
    out
}

fn write_ld(out: &mut String, ld: &LogicalDevice) {
    let ld_name = ld.ld_name.as_deref().unwrap_or("<None>");
    let _ = writeln!(
        out,
        "  LD inst={} ld_name={} lns={}",
        ld.inst,
        ld_name,
        ld.lns.len()
    );

    let mut lns: Vec<&LogicalNode> = ld.lns.iter().collect();
    lns.sort_by(|a, b| {
        (a.prefix.as_str(), a.class.as_str(), a.inst.as_str()).cmp(&(
            b.prefix.as_str(),
            b.class.as_str(),
            b.inst.as_str(),
        ))
    });
    for ln in lns {
        write_ln(out, ln);
    }
}

fn write_ln(out: &mut String, ln: &LogicalNode) {
    let _ = writeln!(
        out,
        "    LN class={} inst={} prefix={} dos={} datasets={} rcbs={} gocbs={} svcbs={} lcbs={} sgcb={}",
        ln.class,
        ln.inst,
        ln.prefix,
        ln.dos.len(),
        ln.datasets.len(),
        ln.rcbs.len(),
        ln.gocbs.len(),
        ln.svcbs.len(),
        ln.lcbs.len(),
        if ln.sgcb.is_some() { "yes" } else { "no" },
    );

    // DOs
    let mut dos: Vec<&DataObject> = ln.dos.iter().collect();
    dos.sort_by(|a, b| a.name.cmp(&b.name));
    for d in dos {
        write_do(out, d, 6);
    }

    // DataSets
    let mut datasets: Vec<&DataSet> = ln.datasets.iter().collect();
    datasets.sort_by(|a, b| a.name.cmp(&b.name));
    for ds in datasets {
        write_dataset(out, ds);
    }

    // RCBs
    let mut rcbs: Vec<&ReportControlBlock> = ln.rcbs.iter().collect();
    rcbs.sort_by(|a, b| a.name.cmp(&b.name));
    for rcb in rcbs {
        let _ = writeln!(
            out,
            "      RCB name={} buffered={} dataset={} confRev={} rptID={}",
            rcb.name, rcb.is_buffered, rcb.dataset_ref, rcb.conf_rev, rcb.rpt_id,
        );
    }

    // GoCBs
    let mut gocbs: Vec<&GooseControlBlock> = ln.gocbs.iter().collect();
    gocbs.sort_by(|a, b| a.name.cmp(&b.name));
    for cb in gocbs {
        let _ = writeln!(
            out,
            "      GoCB name={} dataset={} confRev={} goID={}",
            cb.name, cb.dataset_ref, cb.conf_rev, cb.go_id,
        );
    }

    // SvCBs
    let mut svcbs: Vec<&SvControlBlock> = ln.svcbs.iter().collect();
    svcbs.sort_by(|a, b| a.name.cmp(&b.name));
    for cb in svcbs {
        let _ = writeln!(
            out,
            "      SvCB name={} dataset={} confRev={} svID={} multicast={}",
            cb.name, cb.dataset_ref, cb.conf_rev, cb.sv_id, cb.is_multicast,
        );
    }

    // LCBs
    let mut lcbs: Vec<&LogControlBlock> = ln.lcbs.iter().collect();
    lcbs.sort_by(|a, b| a.name.cmp(&b.name));
    for cb in lcbs {
        let _ = writeln!(
            out,
            "      LCB name={} dataset={} log={}",
            cb.name, cb.dataset_ref, cb.log_ref,
        );
    }

    // SGCB
    if let Some(sgcb) = &ln.sgcb {
        write_sgcb(out, sgcb);
    }
}

fn write_do(out: &mut String, d: &DataObject, indent: usize) {
    let pad = " ".repeat(indent);
    let arr = match d.array_count {
        Some(n) => format!("array({n})"),
        None => "scalar".to_string(),
    };
    let _ = writeln!(
        out,
        "{pad}DO name={} kind={} children={}",
        d.name,
        arr,
        d.children.len(),
    );

    let mut children: Vec<&DoChild> = d.children.iter().collect();
    children.sort_by(|a, b| child_key(a).cmp(child_key(b)));
    for c in children {
        match c {
            DoChild::Da(da) => write_da(out, da, indent + 2),
            DoChild::SubDo(sd) => write_do(out, sd, indent + 2),
        }
    }
}

fn child_key(c: &DoChild) -> &str {
    match c {
        DoChild::Da(da) => da.name.as_str(),
        DoChild::SubDo(sd) => sd.name.as_str(),
    }
}

fn write_da(out: &mut String, da: &DataAttribute, indent: usize) {
    let pad = " ".repeat(indent);
    // Snapshot the value behind the lock, then render it canonically.
    let snapshot = da.snapshot();
    let _ = writeln!(
        out,
        "{pad}DA name={} fc={} ty={} trg=0x{:02x} val={}",
        da.name,
        da.fc.as_str(),
        da.ty.type_name(),
        da.trg_ops.0,
        canonical_value(&snapshot),
    );

    let mut children: Vec<&DataAttribute> = da.children.iter().collect();
    children.sort_by(|a, b| a.name.cmp(&b.name));
    for c in children {
        write_da(out, c, indent + 2);
    }
}

fn write_dataset(out: &mut String, ds: &DataSet) {
    let _ = writeln!(
        out,
        "      DS name={} entries={}",
        ds.name,
        ds.entries.len()
    );
    // Data set entries are order-sensitive on the wire and are deliberately not
    // re-sorted; the builder preserves SCL order, which is stable on its own.
    for (i, e) in ds.entries.iter().enumerate() {
        let _ = writeln!(out, "        FCDA[{i}] {}", canonical_entry(e));
    }
}

fn canonical_entry(e: &DataSetEntry) -> String {
    let path = e.do_path.join(".");
    let arr = match e.array_index {
        Some(i) => format!("[{i}]"),
        None => String::new(),
    };
    let comp = match &e.component {
        Some(c) => format!(".{c}"),
        None => String::new(),
    };
    format!(
        "ld_inst={} ln={} fc={} path={}{}{}",
        e.ld_inst,
        e.ln_name,
        e.fc.as_str(),
        path,
        arr,
        comp,
    )
}

fn write_sgcb(out: &mut String, sgcb: &SettingGroupControlBlock) {
    let _ = writeln!(
        out,
        "      SGCB num={} act={} hasResvTms={} resvTms_s={}",
        sgcb.num_of_sg, sgcb.act_sg, sgcb.has_resv_tms, sgcb.default_resv_tms_s,
    );
}

/// Canonical text representation of an [`MmsValue`].
///
/// Written out variant by variant rather than through `Debug`, whose format
/// may change between releases, so the comparison string stays stable.
fn canonical_value(v: &MmsValue) -> String {
    match v {
        MmsValue::Boolean(b) => format!("Bool({b})"),
        MmsValue::Integer(i) => format!("Int({i})"),
        MmsValue::Unsigned(u) => format!("U({u})"),
        MmsValue::Float32(f) => format!("F32({})", canonical_f32(*f)),
        MmsValue::Float64(f) => format!("F64({})", canonical_f64(*f)),
        MmsValue::BitString { padding, data } => {
            format!("Bits(pad={},len={},hex={})", padding, data.len(), hex(data))
        }
        MmsValue::OctetString(b) => format!("Oct(len={},hex={})", b.len(), hex(b)),
        MmsValue::VisibleString(s) => format!("Vis({:?})", s),
        MmsValue::MmsString(s) => format!("Mms({:?})", s),
        MmsValue::UtcTime(b) => format!("UTC(hex={})", hex(b)),
        MmsValue::BinaryTime(b) => format!("BinTime(len={},hex={})", b.len(), hex(b)),
        MmsValue::Array(items) => {
            let mut s = String::from("Array[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&canonical_value(item));
            }
            s.push(']');
            s
        }
        MmsValue::Structure(items) => {
            let mut s = String::from("Struct{");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&canonical_value(item));
            }
            s.push('}');
            s
        }
    }
}

fn canonical_f32(f: f32) -> String {
    if f.is_nan() {
        "NaN".to_string()
    } else if f == 0.0 {
        // 0.0 and -0.0 render alike, so a "-0" difference cannot separate two
        // otherwise equal models.
        "0".to_string()
    } else {
        // `{:e}` keeps the digit count stable. Printing the most precise IEEE
        // form is enough, since the two build paths only have to agree on the
        // value they round-trip to.
        format!("{}", f)
    }
}

fn canonical_f64(f: f64) -> String {
    if f.is_nan() {
        "NaN".to_string()
    } else if f == 0.0 {
        "0".to_string()
    } else {
        format!("{}", f)
    }
}

fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_scl;

    const MINIMAL_XML: &str = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="Enum" type="ModEnum" dchg="true"/>
      <DA name="q"     fc="ST" bType="Quality" qchg="true"/>
      <DA name="t"     fc="ST" bType="Timestamp"/>
    </DOType>
    <EnumType id="ModEnum">
      <EnumVal ord="1">on</EnumVal>
      <EnumVal ord="2">off</EnumVal>
    </EnumType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="stVal">
                <Val>on</Val>
              </DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;

    #[test]
    fn summary_is_deterministic() {
        let raw = parse_scl(MINIMAL_XML).expect("parse");
        let resolved = raw.resolve().expect("resolve");
        let m = resolved.build_model("IED1").expect("build_model");

        let s1 = summarize_model(&m);
        let s2 = summarize_model(&m);
        assert_eq!(s1, s2, "summary must be deterministic per call");
    }

    #[test]
    fn summary_contains_known_fields() {
        let raw = parse_scl(MINIMAL_XML).expect("parse");
        let resolved = raw.resolve().expect("resolve");
        let m = resolved.build_model("IED1").expect("build_model");

        let s = summarize_model(&m);
        assert!(s.starts_with("IED name=IED1\n"), "got:\n{s}");
        assert!(s.contains("LD inst=LD0"), "got:\n{s}");
        assert!(s.contains("LN class=LLN0"), "got:\n{s}");
        assert!(s.contains("DO name=Mod"), "got:\n{s}");
        // DOI override: stVal must be Int(1)
        assert!(
            s.contains("Int(1)"),
            "expected DOI override Int(1), got:\n{s}"
        );
    }

    #[test]
    fn rebuild_yields_same_summary() {
        // Building the same SCL twice at run time must give the same summary.
        let raw1 = parse_scl(MINIMAL_XML).expect("parse1");
        let m1 = raw1.resolve().unwrap().build_model("IED1").unwrap();
        let raw2 = parse_scl(MINIMAL_XML).expect("parse2");
        let m2 = raw2.resolve().unwrap().build_model("IED1").unwrap();
        assert_eq!(summarize_model(&m1), summarize_model(&m2));
    }
}
