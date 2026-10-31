//! Registration of the control blocks a model declares.
//!
//! [`IedServer::register_from_model`] registers, in one call, every data set,
//! report control block instance, GOOSE control block, log control block and
//! controllable data object of the served model, so an application serving an
//! SCL file needs no registration code of its own. Nothing is registered
//! unless the application calls it; a server built from a model serves only
//! the setting group control blocks on its own.
//!
//! IEC 61850 does not require a server to register what its model declares;
//! this is a convenience over the individual `register_*` calls, which remain
//! available for a block the model does not declare.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iec61850_goose::{CommParameters, GoosePublisher};
use iec61850_model::{DataSetEntry, IedModel, LogicalDevice, LogicalNode};

use crate::error::{Result, ServerError};
use crate::goose_mapping::GoCBHandle;
use crate::logging::{InMemoryLogStorage, LogControl, LogControlBlock, LogStorage};
use crate::reporting::multi_instance::{instance_paths, register_rcb_instances, trigger_options};
use crate::reporting::{Dataset, DatasetEntry, DatasetError};
use crate::server::IedServer;

/// Creates the storage of a log, given its reference `<LD>/<LN>$<logName>`.
pub type LogStorageFactory = Arc<dyn Fn(&str) -> Arc<dyn LogStorage> + Send + Sync>;

/// Gives the communication parameters of the publisher of a GOOSE control
/// block, given its reference `<LD>/<LN>$GO$<name>`.
pub type GooseCommFactory = Arc<dyn Fn(&str) -> CommParameters + Send + Sync>;

/// What [`IedServer::register_from_model_with`] needs beyond the model.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct FromModelOptions {
    /// Creates the storage of each log the log control blocks write to, once
    /// per log; `None` gives each log an unbounded [`InMemoryLogStorage`].
    pub log_storage: Option<LogStorageFactory>,
    /// Gives the destination of each GOOSE publication; `None` gives every
    /// publisher APPID 0 and the destination `01-0C-CD-01-00-00`.
    pub goose_comm: Option<GooseCommFactory>,
}

impl std::fmt::Debug for FromModelOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromModelOptions")
            .field("log_storage", &self.log_storage.is_some())
            .field("goose_comm", &self.goose_comm.is_some())
            .finish()
    }
}

impl FromModelOptions {
    /// Returns the defaults: in-memory logs and placeholder GOOSE destinations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the factory of the log storages.
    pub fn with_log_storage(mut self, factory: LogStorageFactory) -> Self {
        self.log_storage = Some(factory);
        self
    }

    /// Sets the communication parameters of the GOOSE publishers.
    pub fn with_goose_comm(mut self, factory: GooseCommFactory) -> Self {
        self.goose_comm = Some(factory);
        self
    }
}

/// How many items of each kind [`IedServer::register_from_model`] found in the
/// model and serves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FromModelSummary {
    /// Data sets.
    pub data_sets: usize,
    /// Unbuffered report control block instances.
    pub urcbs: usize,
    /// Buffered report control block instances.
    pub brcbs: usize,
    /// GOOSE control blocks.
    pub gocbs: usize,
    /// Log control blocks.
    pub lcbs: usize,
    /// Setting group control blocks, which the server serves from the model
    /// whether or not this call is made.
    pub sgcbs: usize,
    /// Control objects newly registered; one already registered is counted
    /// out and kept as it is.
    pub control_objects: usize,
}

/// The default destination of a GOOSE publication, the first address of the
/// GOOSE multicast range of IEC 61850-8-1 Annex B.
const DEFAULT_GOOSE_DESTINATION: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00];

impl IedServer {
    /// Registers every control block the model declares, with the defaults of
    /// [`FromModelOptions`].
    ///
    /// See [`register_from_model_with`](Self::register_from_model_with).
    ///
    /// # Errors
    ///
    /// As [`register_from_model_with`](Self::register_from_model_with).
    pub fn register_from_model(&self) -> Result<FromModelSummary> {
        self.register_from_model_with(&FromModelOptions::default())
    }

    /// Registers every control block the model declares.
    ///
    /// For each logical node of each logical device:
    ///
    /// - each data set, as `<LN>$<name>`, its members bound to the attributes
    ///   of the model; a member that names a data object or a constructed
    ///   attribute is bound as the basic-type attributes below it under its
    ///   functional constraint;
    /// - each instance of each report control block, named as the model
    ///   declares (`<name>01` to `<name>NN` when indexed), with its `RptID`,
    ///   `DatSet`, `TrgOps`, `OptFlds`, `BufTm`, `IntgPd` and `ConfRev`; each
    ///   instance has its own state and, when buffered, its own buffer;
    /// - each GOOSE control block, with a publisher carrying its `GoID`,
    ///   `DatSet` and `ConfRev`; the application finds the publisher through
    ///   [`gocb_registry`](Self::gocb_registry) and transmits its frames, and
    ///   [`FromModelOptions::goose_comm`] gives its destination, which the
    ///   model does not hold. `MinTime` and `MaxTime` are those of
    ///   [`iec61850_goose::RetransIntervals::default`];
    /// - each log control block, with its `DatSet`, `TrgOps`, `IntgPd`,
    ///   reason code setting and initial `LogEna`, writing to the log its
    ///   `LogRef` names; a bare log name is a log of `LLN0` of the same
    ///   logical device (IEC 61850-6 §9.3.9). Control blocks naming the same
    ///   log share its storage, which [`FromModelOptions::log_storage`]
    ///   creates;
    /// - each data object whose `ctlModel` is other than status-only, through
    ///   [`ControlObjectsRegistry::register_from_model`](crate::control::ControlObjectsRegistry::register_from_model).
    ///
    /// Call it after the server is built and before it starts, then install
    /// the control handlers on the registered control objects.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::AlreadyRegistered`] when a data set, report,
    /// GOOSE or log control block of the model is already registered under
    /// the same reference, and `InvalidModel` when two of them, report control
    /// block instances included, have the same reference, when a data set member does not
    /// resolve, names an element past the end of its array, resolves to no attribute or to more
    /// than [`DatasetEntry::MAX_LEAVES`] attributes, when a
    /// control block names a data set of another logical device or one the
    /// server does not hold, or when a GOOSE control block names no data set.
    /// Nothing is registered when an error is returned. A control object
    /// already registered is left as it is, its handlers included.
    pub fn register_from_model_with(&self, options: &FromModelOptions) -> Result<FromModelSummary> {
        let model = self.model();
        let plan = Plan::of(&model)?;
        self.check_free(&plan)?;

        // Everything that can fail is prepared before the first registration.
        let rcb_data_sets = plan
            .rcbs
            .iter()
            .map(|rcb| self.rcb_data_set(&plan, rcb))
            .collect::<Result<Vec<_>>>()?;
        let publishers = plan
            .gocbs
            .iter()
            .map(|gocb| {
                let comm = match &options.goose_comm {
                    Some(factory) => factory(&gocb.reference),
                    None => CommParameters::new(0, DEFAULT_GOOSE_DESTINATION),
                };
                let go_id = Some(gocb.go_id.clone()).filter(|id| !id.is_empty());
                GoosePublisher::new(
                    comm,
                    gocb.reference.clone(),
                    go_id,
                    gocb.data_set.clone(),
                    gocb.conf_rev,
                )
                .map_err(|e| {
                    ServerError::InvalidModel(format!(
                        "GOOSE control block {}: {e}",
                        gocb.reference
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut summary = FromModelSummary::default();
        for (domain, ds) in &plan.data_sets {
            self.register_dataset(domain.clone(), ds.clone());
            summary.data_sets += 1;
        }
        for (rcb, dataset) in plan.rcbs.iter().zip(&rcb_data_sets) {
            let n = register_rcb_instances(
                self,
                &rcb.domain,
                &rcb.ln_name,
                &rcb.block,
                &dataset.name,
                dataset,
            )?;
            if rcb.block.is_buffered {
                summary.brcbs += n;
            } else {
                summary.urcbs += n;
            }
        }
        for (gocb, publisher) in plan.gocbs.iter().zip(publishers) {
            self.register_gocb(Arc::new(GoCBHandle::new(
                gocb.domain.clone(),
                gocb.ln_name.clone(),
                gocb.name.clone(),
                Arc::new(Mutex::new(publisher)),
            )));
            summary.gocbs += 1;
        }
        let mut logs: HashMap<String, Arc<dyn LogStorage>> = HashMap::new();
        for lcb in &plan.lcbs {
            let storage = logs
                .entry(lcb.log_ref.clone())
                .or_insert_with(|| match &options.log_storage {
                    Some(factory) => factory(&lcb.log_ref),
                    None => Arc::new(InMemoryLogStorage::new()),
                })
                .clone();
            let mut block = LogControlBlock::new(lcb.name.clone())
                .with_log_ref(lcb.log_ref.clone())
                .with_trg_ops(trigger_options(lcb.trg_ops))
                .with_intg_pd_ms(lcb.intg_pd_ms)
                .with_default_enabled(lcb.log_ena);
            if let Some(ds) = &lcb.data_set {
                block = block.with_dataset(ds.clone());
            }
            block.include_reason_code = lcb.reason_code;
            // Binding the storage enables a block that starts enabled and
            // names a data set.
            let control = LogControl::new(lcb.mms_path(), block).with_storage(storage);
            self.register_log_control(lcb.domain.clone(), lcb.item(), Arc::new(control));
            summary.lcbs += 1;
        }
        summary.control_objects = self.control_objects().register_from_model(&model);
        summary.sgcbs = self.setting_groups().len();
        Ok(summary)
    }

    /// The data set a report control block of `plan` reports: one of the plan
    /// or one the server holds, or an empty one when the block names none.
    fn rcb_data_set(&self, plan: &Plan, rcb: &RcbPlan) -> Result<Dataset> {
        let Some(key) = &rcb.data_set else {
            return Ok(Dataset::new(""));
        };
        if let Some((_, ds)) = plan
            .data_sets
            .iter()
            .find(|(domain, ds)| *domain == key.0 && ds.name == key.1)
        {
            return Ok(ds.clone());
        }
        self.dataset_registry()
            .read()
            .ok()
            .and_then(|g| g.get(key).map(|ds| ds.as_ref().clone()))
            .ok_or_else(|| {
                ServerError::InvalidModel(format!(
                    "report control block {}/{}.{} names the data set {}, which the server does not hold",
                    rcb.domain, rcb.ln_name, rcb.block.name, key.1
                ))
            })
    }

    /// Fails when an item of `plan` is registered already.
    fn check_free(&self, plan: &Plan) -> Result<()> {
        let taken = |reference: String| Err(ServerError::AlreadyRegistered { reference });
        {
            let data_sets = self.dataset_registry();
            let g = data_sets.read().map_err(|_| poisoned("data set"))?;
            if let Some((domain, ds)) = plan
                .data_sets
                .iter()
                .find(|(domain, ds)| g.contains_key(&(domain.clone(), ds.name.clone())))
            {
                return taken(format!("{domain}/{}", ds.name));
            }
        }
        {
            let engine = self.reporting_engine();
            let g = engine.lock().map_err(|_| poisoned("reporting engine"))?;
            for rcb in &plan.rcbs {
                for path in instance_paths(&rcb.domain, &rcb.ln_name, &rcb.block) {
                    if g.get_rcb(&path).is_some() || g.get_brcb(&path).is_some() {
                        return taken(path);
                    }
                }
            }
        }
        let gocbs = self.gocb_registry();
        if let Some(gocb) = plan
            .gocbs
            .iter()
            .find(|cb| gocbs.find(&cb.domain, &cb.ln_name, &cb.name).is_some())
        {
            return taken(gocb.reference.clone());
        }
        let logs = self.log_controls();
        let g = logs.read().map_err(|_| poisoned("log control"))?;
        if let Some(lcb) = plan
            .lcbs
            .iter()
            .find(|lcb| g.contains_key(&(lcb.domain.clone(), lcb.item())))
        {
            return taken(lcb.mms_path());
        }
        Ok(())
    }
}

fn poisoned(what: &str) -> ServerError {
    ServerError::InvalidModel(format!("the {what} registry lock is poisoned"))
}

// ─────────────────────────────────────────────────────────────────────────────
// What a model declares, resolved before anything is registered
// ─────────────────────────────────────────────────────────────────────────────

struct Plan {
    data_sets: Vec<(String, Dataset)>,
    rcbs: Vec<RcbPlan>,
    gocbs: Vec<GocbPlan>,
    lcbs: Vec<LcbPlan>,
}

struct RcbPlan {
    domain: String,
    ln_name: String,
    block: iec61850_model::ReportControlBlock,
    /// The registry key of the data set, `None` when the block names none.
    data_set: Option<(String, String)>,
}

struct GocbPlan {
    domain: String,
    ln_name: String,
    name: String,
    reference: String,
    go_id: String,
    /// The data set reference, `<LD>/<LN>$<name>`.
    data_set: String,
    conf_rev: u32,
}

struct LcbPlan {
    domain: String,
    ln_name: String,
    name: String,
    /// The data set as the log control block names it, `<LN>$<name>`.
    data_set: Option<String>,
    log_ref: String,
    log_ena: bool,
    reason_code: bool,
    trg_ops: iec61850_model::TrgOps,
    intg_pd_ms: u32,
}

impl LcbPlan {
    fn item(&self) -> String {
        format!("{}$LG${}", self.ln_name, self.name)
    }

    fn mms_path(&self) -> String {
        format!("{}/{}", self.domain, self.item())
    }
}

impl Plan {
    fn of(model: &IedModel) -> Result<Self> {
        let mut plan = Plan {
            data_sets: Vec::new(),
            rcbs: Vec::new(),
            gocbs: Vec::new(),
            lcbs: Vec::new(),
        };
        for ld in &model.lds {
            let domain = ld.domain_name(&model.ied_name);
            for ln in &ld.lns {
                let ln_name = ln.full_name();
                for ds in &ln.datasets {
                    let name = format!("{ln_name}${}", ds.name);
                    let mut out = Dataset::new(name.clone());
                    for entry in &ds.entries {
                        out.push(member_entry(model, ld, entry).map_err(|why| {
                            ServerError::InvalidModel(format!(
                                "data set {domain}/{name}: member {entry} {why}"
                            ))
                        })?);
                    }
                    plan.data_sets.push((domain.clone(), out));
                }
            }
        }
        let resolve = |domain: &str, ln: &LogicalNode, reference: &str, block: &str| {
            let key = data_set_key(domain, &ln.full_name(), reference);
            if key.0 != domain {
                return Err(ServerError::InvalidModel(format!(
                    "{block} names the data set {reference} of another logical device"
                )));
            }
            Ok(key)
        };
        for ld in &model.lds {
            let domain = ld.domain_name(&model.ied_name);
            for ln in &ld.lns {
                let ln_name = ln.full_name();
                for rcb in &ln.rcbs {
                    let data_set = (!rcb.dataset_ref.is_empty())
                        .then(|| {
                            resolve(
                                &domain,
                                ln,
                                &rcb.dataset_ref,
                                &format!("report control block {domain}/{ln_name}.{}", rcb.name),
                            )
                        })
                        .transpose()?;
                    plan.rcbs.push(RcbPlan {
                        domain: domain.clone(),
                        ln_name: ln_name.clone(),
                        block: rcb.clone(),
                        data_set,
                    });
                }
                for gocb in &ln.gocbs {
                    let reference = format!("{domain}/{ln_name}$GO${}", gocb.name);
                    if gocb.dataset_ref.is_empty() {
                        return Err(ServerError::InvalidModel(format!(
                            "GOOSE control block {reference} names no data set"
                        )));
                    }
                    let key = resolve(&domain, ln, &gocb.dataset_ref, &reference)?;
                    plan.gocbs.push(GocbPlan {
                        domain: domain.clone(),
                        ln_name: ln_name.clone(),
                        name: gocb.name.clone(),
                        reference,
                        go_id: gocb.go_id.clone(),
                        data_set: format!("{}/{}", key.0, key.1),
                        conf_rev: gocb.conf_rev,
                    });
                }
                for lcb in &ln.lcbs {
                    let data_set = (!lcb.dataset_ref.is_empty())
                        .then(|| {
                            resolve(
                                &domain,
                                ln,
                                &lcb.dataset_ref,
                                &format!("log control block {domain}/{ln_name}.{}", lcb.name),
                            )
                        })
                        .transpose()?
                        .map(|(_, name)| name);
                    plan.lcbs.push(LcbPlan {
                        domain: domain.clone(),
                        ln_name: ln_name.clone(),
                        name: lcb.name.clone(),
                        data_set,
                        log_ref: log_reference(&domain, &lcb.log_ref),
                        log_ena: lcb.log_ena,
                        reason_code: lcb.reason_code,
                        trg_ops: lcb.trg_ops,
                        intg_pd_ms: lcb.intg_pd_ms,
                    });
                }
            }
        }
        plan.check_unique()?;
        Ok(plan)
    }

    /// Fails when two items of the plan would be registered under one
    /// reference, such as `Foo` indexed with two instances and `Foo01`.
    fn check_unique(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        let references = self
            .data_sets
            .iter()
            .map(|(domain, ds)| format!("{domain}/{}", ds.name))
            .chain(
                self.rcbs
                    .iter()
                    .flat_map(|rcb| instance_paths(&rcb.domain, &rcb.ln_name, &rcb.block)),
            )
            .chain(self.gocbs.iter().map(|gocb| gocb.reference.clone()))
            .chain(self.lcbs.iter().map(LcbPlan::mms_path));
        for reference in references {
            if !seen.insert(reference.clone()) {
                return Err(ServerError::InvalidModel(format!(
                    "the model declares two items named {reference}"
                )));
            }
        }
        Ok(())
    }
}

/// The registry key of the data set `reference` names, for a control block of
/// the logical node `ln_name` of `domain`: `<LD>/<LN>$<name>`, `<LN>$<name>`
/// in the same logical device, or a bare name in the same logical node
/// (IEC 61850-6 §9.3.8, §9.3.9).
fn data_set_key(domain: &str, ln_name: &str, reference: &str) -> (String, String) {
    match reference.split_once('/') {
        Some((d, name)) => (d.to_string(), name.to_string()),
        None if reference.contains('$') => (domain.to_string(), reference.to_string()),
        None => (domain.to_string(), format!("{ln_name}${reference}")),
    }
}

/// The reference of the log a log control block of `domain` names: kept when
/// it names a domain, `<domain>/<LN>$<logName>` for `<LN>$<logName>`, and a
/// log of `LLN0` for a bare log name (IEC 61850-6 §9.3.9 Table 26).
fn log_reference(domain: &str, log_ref: &str) -> String {
    if log_ref.contains('/') {
        log_ref.to_string()
    } else if log_ref.contains('$') {
        format!("{domain}/{log_ref}")
    } else {
        format!("{domain}/LLN0${log_ref}")
    }
}

/// Binds a data set member of the model to the node it names, an FCD or an
/// FCDA of any type, or an element of an array its index selects; the error
/// says why it does not resolve.
fn member_entry(
    model: &IedModel,
    owner: &LogicalDevice,
    entry: &DataSetEntry,
) -> core::result::Result<DatasetEntry, &'static str> {
    let names_no_device = || {
        !entry.ld_inst.is_empty()
            && model.ld_by_inst(&entry.ld_inst).is_none()
            && model.ld_by_domain(&entry.ld_inst).is_none()
    };
    DatasetEntry::from_data_set_entry(model, owner, entry).map_err(|e| match e {
        DatasetError::MemberNotFound { .. } if names_no_device() => {
            "names no logical device of the model"
        }
        DatasetError::MemberNotFound { .. } => "does not resolve under its functional constraint",
        DatasetError::TooLarge { .. } => "holds more attributes than a member may",
        _ if entry.array_index.is_some() => "names no element of an array on its path",
        _ => "is not a valid member path",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{cdc, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, FC};

    /// A member whose logical device does not exist says so, apart from one
    /// whose device exists but whose node does not resolve.
    #[test]
    fn a_member_names_why_it_does_not_resolve() {
        let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(cdc::sps("Ind1", cdc::CdcOptions::NONE))
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let owner = model.ld_by_inst("LD0").unwrap();
        let entry = |ld_inst: &str, do_name: &str| {
            let mut e = DataSetEntry::new("GGIO1", FC::St, vec![do_name.into()]);
            e.ld_inst = ld_inst.into();
            e
        };
        assert_eq!(
            member_entry(&model, owner, &entry("LD9", "Ind1")).unwrap_err(),
            "names no logical device of the model"
        );
        assert_eq!(
            member_entry(&model, owner, &entry("LD0", "NoSuchDo")).unwrap_err(),
            "does not resolve under its functional constraint"
        );
        assert_eq!(
            member_entry(&model, owner, &entry("", "NoSuchDo")).unwrap_err(),
            "does not resolve under its functional constraint"
        );
        assert!(member_entry(&model, owner, &entry("IED1LD0", "Ind1")).is_ok());
    }
}
