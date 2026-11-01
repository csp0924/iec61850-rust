//! The Communication section: the stage 2 checks of its references, and its
//! mapping onto the model of one IED.
//!
//! A `<ConnectedAP>` names an IED and one of its access points (IEC 61850-6
//! §9.4.2, and the `refConnectedAP2IED` key reference of the schema), and a
//! `<GSE>` or `<SMV>` names a control block of the `LLN0` of a logical device
//! of that access point (§9.4.4, §9.4.5). Stage 2 rejects a reference that
//! names nothing, so the model builder can attach every address it finds.
//!
//! A `<P>` value is checked against the form its type prescribes: the
//! patterns of the `tP_` types of the schema and the character rules of
//! IEC 61850-8-1 §25.2 Table 162, §25.3.2 Table 163 and §25.3.3 Table 164, and
//! of IEC 61850-9-2 Clause 11 Table 19. A value that breaks them fails the
//! model build of the IED it belongs to; stage 2 only warns about it, so an
//! invalid address of another IED of an SCD does not prevent building this
//! one.
//!
//! The run-time build and the build script share [`connected_access_points`],
//! [`gse_addresses`], [`smv_addresses`], [`attach_gse`] and [`attach_smv`], so
//! a generated model carries the same addressing as one built at run time.

use iec61850_model::comm::{
    check_parameter, Address, AddressError, ConnectedAccessPoint, GseAddress,
};
use iec61850_model::tree::IedModel;

use crate::error::{ErrorKind, SclParseError, SourceSpan};
use crate::raw::{RawAddress, RawConnectedAp, RawScl, RawSubNetwork};

/// Checks that every `<ConnectedAP>` names an access point of an IED of the
/// file, that every `<GSE>` and `<SMV>` names a control block of that access
/// point, and that no `<GSE>` declares a `MinTime` above its `MaxTime`, and
/// warns about every `<P>` whose value its type does not accept.
///
/// # Errors
///
/// [`ErrorKind::SemanticConflict`] naming the attribute whose reference does
/// not resolve, or the `MinTime` above the `MaxTime`.
pub(crate) fn check_communication(raw: &RawScl) -> Result<(), SclParseError> {
    let Some(communication) = raw.communication.as_ref() else {
        return Ok(());
    };
    for sub_network in &communication.sub_networks {
        for cap in &sub_network.connected_aps {
            let ap_path = connected_ap_path(sub_network, cap);
            warn_invalid_parameters(cap);
            let conflict = |path: &str, attr: &str, detail: String| {
                SclParseError::at(cap.span, path, ErrorKind::SemanticConflict { detail })
                    .with_attribute(attr)
            };
            let ied = raw
                .ieds
                .iter()
                .find(|i| i.name == cap.ied_name)
                .ok_or_else(|| {
                    conflict(
                        &ap_path,
                        "iedName",
                        format!("the file declares no IED named `{}`", cap.ied_name),
                    )
                })?;
            let ap = ied
                .access_points
                .iter()
                .find(|a| a.name == cap.ap_name)
                .ok_or_else(|| {
                    conflict(
                        &ap_path,
                        "apName",
                        format!(
                            "the IED `{}` declares no access point named `{}`",
                            cap.ied_name, cap.ap_name
                        ),
                    )
                })?;
            let lln0 = |ld_inst: &str| {
                ap.server
                    .as_ref()?
                    .logical_devices
                    .iter()
                    .find(|ld| ld.inst == ld_inst)?
                    .logical_nodes
                    .iter()
                    .find(|ln| ln.ln_class == "LLN0")
            };
            for gse in &cap.gses {
                let path = format!(
                    "{ap_path}/GSE[ldInst=\"{}\",cbName=\"{}\"]",
                    gse.ld_inst, gse.cb_name
                );
                let at = |attr: &str, detail: String| {
                    SclParseError::at(
                        gse.span,
                        path.clone(),
                        ErrorKind::SemanticConflict { detail },
                    )
                    .with_attribute(attr)
                };
                let Some(ln) = lln0(&gse.ld_inst) else {
                    return Err(at("ldInst", no_ld(cap, &gse.ld_inst)));
                };
                if !ln.gse_controls.iter().any(|c| c.name == gse.cb_name) {
                    return Err(at(
                        "cbName",
                        format!(
                            "the LLN0 of the logical device `{}` declares no GSEControl named `{}`",
                            gse.ld_inst, gse.cb_name
                        ),
                    ));
                }
                if let (Some(min), Some(max)) = (gse.min_time_ms, gse.max_time_ms) {
                    if min > max {
                        return Err(SclParseError::at(
                            gse.span,
                            path.clone(),
                            ErrorKind::SemanticConflict {
                                detail: format!(
                                    "MinTime {min} ms exceeds MaxTime {max} ms; a repetition \
                                     interval lies between the two (IEC 61850-8-1 §18.1.2.5.1)"
                                ),
                            },
                        ));
                    }
                }
            }
            for smv in &cap.smvs {
                let path = format!(
                    "{ap_path}/SMV[ldInst=\"{}\",cbName=\"{}\"]",
                    smv.ld_inst, smv.cb_name
                );
                let at = |attr: &str, detail: String| {
                    SclParseError::at(
                        smv.span,
                        path.clone(),
                        ErrorKind::SemanticConflict { detail },
                    )
                    .with_attribute(attr)
                };
                let Some(ln) = lln0(&smv.ld_inst) else {
                    return Err(at("ldInst", no_ld(cap, &smv.ld_inst)));
                };
                if !ln.smv_controls.iter().any(|c| c.name == smv.cb_name) {
                    return Err(at(
                        "cbName",
                        format!(
                            "the LLN0 of the logical device `{}` declares no \
                             SampledValueControl named `{}`",
                            smv.ld_inst, smv.cb_name
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Warns about each `<P>` of the connected access point, and of its `<GSE>`
/// and `<SMV>`, whose value its type does not accept.
fn warn_invalid_parameters(cap: &RawConnectedAp) {
    let addresses = cap
        .address
        .iter()
        .chain(cap.gses.iter().filter_map(|g| g.address.as_ref()))
        .chain(cap.smvs.iter().filter_map(|m| m.address.as_ref()));
    for p in addresses.flat_map(|a| &a.parameters) {
        if let Err(e) = check_parameter(&p.p_type, &p.value) {
            tracing::warn!(
                target: "iec61850_scl::communication",
                line = p.span.line,
                col = p.span.col,
                "{e} in the Communication section of the IED `{}`; the model of that IED \
                 cannot be built",
                cap.ied_name,
            );
        }
    }
}

/// Converts an `<Address>` into an [`Address`], checking each `<P>`.
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] at the first `<P>` whose type or value
/// is refused; a bad type names the `type` attribute.
fn to_address(raw: &RawAddress, path: &str) -> Result<Address, SclParseError> {
    let mut address = Address::new();
    for p in &raw.parameters {
        address
            .push(p.p_type.clone(), p.value.clone())
            .map_err(|e| address_error(e, p.span, format!("{path}/Address/P")))?;
    }
    Ok(address)
}

/// Converts a refused `<P>` into an [`SclParseError`] at the element: a bad
/// type names the `type` attribute, a bad value the element text.
fn address_error(e: AddressError, span: SourceSpan, path: String) -> SclParseError {
    match e {
        AddressError::InvalidType { p_type, .. } => SclParseError::at(
            span,
            path,
            ErrorKind::AttributeValueInvalid {
                name: "type".to_string(),
                expected_type: "a predefined address type, or an extension type of an \
                                upper-case letter followed by letters, digits and hyphens"
                    .to_string(),
                raw_value: p_type,
                cause: None,
            },
        )
        .with_attribute("type"),
        AddressError::InvalidValue {
            p_type,
            value,
            expected,
            ..
        } => SclParseError::at(
            span,
            path,
            ErrorKind::AttributeValueInvalid {
                name: format!("P[type=\"{p_type}\"]"),
                expected_type: expected.to_string(),
                raw_value: value,
                cause: None,
            },
        ),
        other => SclParseError::at(span, path, ErrorKind::Xml(other.to_string())),
    }
}

fn no_ld(cap: &RawConnectedAp, ld_inst: &str) -> String {
    format!(
        "the access point `{}` of the IED `{}` holds no logical device `{}` with an LLN0",
        cap.ap_name, cap.ied_name, ld_inst
    )
}

fn connected_ap_path(sub_network: &RawSubNetwork, cap: &RawConnectedAp) -> String {
    format!(
        "SCL/Communication/SubNetwork[name=\"{}\"]/ConnectedAP[iedName=\"{}\",apName=\"{}\"]",
        sub_network.name, cap.ied_name, cap.ap_name
    )
}

/// Iterates the `<ConnectedAP>` elements of the IED `ied_name`, with their
/// subnetworks, in document order.
fn connected_aps_of<'a>(
    raw: &'a RawScl,
    ied_name: &'a str,
) -> impl Iterator<Item = (&'a RawSubNetwork, &'a RawConnectedAp)> + 'a {
    raw.communication
        .iter()
        .flat_map(|c| &c.sub_networks)
        .flat_map(|n| n.connected_aps.iter().map(move |ap| (n, ap)))
        .filter(move |(_, ap)| ap.ied_name == ied_name)
}

/// Returns the connections of the access points of the IED `ied_name` to
/// subnetworks, in document order.
///
/// Also used by the build-script path through [`crate::__private`].
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] at a `<P>` of the server address whose
/// type or value is refused.
pub fn connected_access_points(
    raw: &RawScl,
    ied_name: &str,
) -> Result<Vec<ConnectedAccessPoint>, SclParseError> {
    connected_aps_of(raw, ied_name)
        .map(|(n, ap)| {
            let mut out = ConnectedAccessPoint::new(n.name.clone(), ap.ap_name.clone());
            out.sub_network_type = n.net_type.clone();
            out.address = ap
                .address
                .as_ref()
                .map(|a| to_address(a, &connected_ap_path(n, ap)))
                .transpose()?;
            Ok(out)
        })
        .collect()
}

/// Returns the addressing of the GOOSE control blocks of the IED `ied_name`
/// as `(ldInst, cbName, addressing)`, one entry per control block.
///
/// A control block addressed in more than one subnetwork keeps the first
/// `<GSE>` in document order, and a warning names the others.
///
/// Also used by the build-script path through [`crate::__private`].
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] at a `<P>` whose type or value is
/// refused.
pub fn gse_addresses(
    raw: &RawScl,
    ied_name: &str,
) -> Result<Vec<(String, String, GseAddress)>, SclParseError> {
    let mut out: Vec<(String, String, GseAddress)> = Vec::new();
    for (n, ap) in connected_aps_of(raw, ied_name) {
        for gse in &ap.gses {
            if out
                .iter()
                .any(|(ld, cb, _)| *ld == gse.ld_inst && *cb == gse.cb_name)
            {
                warn_second_address(n, ap, "GSE", &gse.ld_inst, &gse.cb_name, gse.span.line);
                continue;
            }
            let path = format!(
                "{}/GSE[ldInst=\"{}\",cbName=\"{}\"]",
                connected_ap_path(n, ap),
                gse.ld_inst,
                gse.cb_name
            );
            let parameters = match &gse.address {
                Some(a) => to_address(a, &path)?,
                None => Address::new(),
            };
            let mut address = GseAddress::new(parameters);
            address.min_time_ms = gse.min_time_ms;
            address.max_time_ms = gse.max_time_ms;
            out.push((gse.ld_inst.clone(), gse.cb_name.clone(), address));
        }
    }
    Ok(out)
}

/// Returns the address of the sampled values control blocks of the IED
/// `ied_name` as `(ldInst, cbName, address)`, one entry per control block.
///
/// A control block addressed in more than one subnetwork keeps the first
/// `<SMV>` in document order, and a warning names the others.
///
/// Also used by the build-script path through [`crate::__private`].
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] at a `<P>` whose type or value is
/// refused.
pub fn smv_addresses(
    raw: &RawScl,
    ied_name: &str,
) -> Result<Vec<(String, String, Address)>, SclParseError> {
    let mut out: Vec<(String, String, Address)> = Vec::new();
    for (n, ap) in connected_aps_of(raw, ied_name) {
        for smv in &ap.smvs {
            if out
                .iter()
                .any(|(ld, cb, _)| *ld == smv.ld_inst && *cb == smv.cb_name)
            {
                warn_second_address(n, ap, "SMV", &smv.ld_inst, &smv.cb_name, smv.span.line);
                continue;
            }
            let path = format!(
                "{}/SMV[ldInst=\"{}\",cbName=\"{}\"]",
                connected_ap_path(n, ap),
                smv.ld_inst,
                smv.cb_name
            );
            let address = match &smv.address {
                Some(a) => to_address(a, &path)?,
                None => Address::new(),
            };
            out.push((smv.ld_inst.clone(), smv.cb_name.clone(), address));
        }
    }
    Ok(out)
}

fn warn_second_address(
    sub_network: &RawSubNetwork,
    ap: &RawConnectedAp,
    element: &str,
    ld_inst: &str,
    cb_name: &str,
    line: u32,
) {
    tracing::warn!(
        target: "iec61850_scl::communication",
        line,
        "ignoring the `<{element}>` for `{ld_inst}/{cb_name}` under the access point `{}` of \
         the subnetwork `{}`; an earlier one addresses the same control block",
        ap.ap_name,
        sub_network.name,
    );
}

/// Sets the addressing of the GOOSE control block `cb_name` of the `LLN0` of
/// the logical device `ld_inst`, and returns whether the model holds that
/// control block.
///
/// Also used by the code `iec61850-scl-build` generates, through
/// [`crate::__private`].
pub fn attach_gse(model: &mut IedModel, ld_inst: &str, cb_name: &str, gse: GseAddress) -> bool {
    let cb = model
        .lds
        .iter_mut()
        .find(|ld| ld.inst == ld_inst)
        .and_then(|ld| ld.lns.first_mut())
        .and_then(|ln| ln.gocbs.iter_mut().find(|cb| cb.name == cb_name));
    match cb {
        Some(cb) => {
            cb.gse = Some(gse);
            true
        }
        None => false,
    }
}

/// Sets the address of the sampled values control block `cb_name` of the
/// `LLN0` of the logical device `ld_inst`, and returns whether the model holds
/// that control block.
///
/// Also used by the code `iec61850-scl-build` generates, through
/// [`crate::__private`].
pub fn attach_smv(model: &mut IedModel, ld_inst: &str, cb_name: &str, smv: Address) -> bool {
    let cb = model
        .lds
        .iter_mut()
        .find(|ld| ld.inst == ld_inst)
        .and_then(|ld| ld.lns.first_mut())
        .and_then(|ln| ln.svcbs.iter_mut().find(|cb| cb.name == cb_name));
    match cb {
        Some(cb) => {
            cb.smv = Some(smv);
            true
        }
        None => false,
    }
}
