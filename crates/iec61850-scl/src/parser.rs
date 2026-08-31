//! Streaming SCL parser driven by quick-xml.
//!
//! Two decisions shape it. The document is never buffered as a tree: the
//! parser consumes the reader's event stream and keeps whatever element it is
//! assembling in a chain of `Option` fields, from IED down to logical node.
//! And because quick-xml reports only a byte offset, a line tracker converts
//! that offset into a one-based line and column, so an error can point at the
//! source without a second pass over the input.
//!
//! Character data reaches a value as one run: literal text, entity and
//! character references, and CDATA sections join in document order. The
//! literal ends of a run are trimmed, while a reference replacement and the
//! content of a CDATA section keep the whitespace the document spells out.
//!
//! `<Substation>` and `<Communication>`, direct children of `<SCL>` that carry
//! nothing the model needs, are skipped as whole subtrees. Each skip emits a
//! `tracing::warn!` naming the line, column and element, so nothing disappears
//! silently: a real `.cid` almost always carries a `<Communication>` section
//! with the GSE and SMV publisher addresses, which belong to the communication
//! configuration rather than to the model.

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::reader::Reader;

use crate::attrs::{optional, parse_optional, parse_required, required};
use crate::error::{ErrorKind, SclParseError, SourceSpan};
use crate::raw::{
    OptionFieldsBits, RawAccessPoint, RawBda, RawDaDef, RawDaType, RawDai, RawDataInstance,
    RawDataSet, RawDoDef, RawDoType, RawDoi, RawEnumType, RawEnumValue, RawFcda, RawGseControl,
    RawIed, RawLNodeType, RawLogControl, RawLogicalDevice, RawLogicalNode, RawReportControlBlock,
    RawSampledValueControl, RawScl, RawSdi, RawSdoDef, RawServer, RawVal, SmvOptsBits,
    TriggerOptionsBits,
};

/// Parses an SCL XML string into the stage 1 raw AST.
///
/// # Errors
///
/// [`SclParseError`], always carrying a line, a column and an element path.
pub fn parse(xml: &str) -> Result<RawScl, SclParseError> {
    let mut reader = Reader::from_str(xml);

    let mut state = ParserState::new(xml);
    let mut buf = Vec::new();
    let mut result = RawScl::default();
    // An entity or character reference ends the surrounding text event and
    // arrives as its own event; the fragments accumulate here and reach the
    // handler as one string when the next structural event closes the run.
    let mut pending_text = TextRun::default();

    loop {
        // quick-xml reports the position at the end of the previous event,
        // usually just past a `>` and before some whitespace. Advancing the
        // offset to the next `<` keeps the line and column on the element.
        let event_start_off = advance_to_lt(xml, reader.buffer_position());
        let event = reader.read_event_into(&mut buf).map_err(|e| {
            SclParseError::at(
                state.span_at(event_start_off),
                state.path_str(),
                ErrorKind::Xml(e.to_string()),
            )
        })?;

        match event {
            Event::Start(start) => {
                flush_text(&mut state, &mut pending_text);
                let span = state.span_at(event_start_off);
                handle_start(
                    &mut state,
                    &mut result,
                    &start,
                    span,
                    /* empty = */ false,
                )?;
            }
            Event::Empty(start) => {
                flush_text(&mut state, &mut pending_text);
                let span = state.span_at(event_start_off);
                // An empty element is a start immediately followed by an end.
                handle_start(
                    &mut state,
                    &mut result,
                    &start,
                    span,
                    /* empty = */ true,
                )?;
                handle_end(&mut state, &mut result, name_of(&start), span)?;
            }
            Event::End(end) => {
                flush_text(&mut state, &mut pending_text);
                let span = state.span_at(event_start_off);
                let name = end.name().as_ref().to_string();
                handle_end(&mut state, &mut result, name, span)?;
            }
            Event::Text(text) => {
                // Only meaningful while a handler is waiting for text, that is
                // an EnumVal name or a Val. Other text is ignored.
                if state.text_target != TextTarget::None {
                    pending_text.push_literal(&text.xml10_content());
                }
            }
            Event::GeneralRef(reference) => {
                // A reference such as `&amp;` or `&#10;` ends the text event
                // that precedes it; its replacement rejoins the same run.
                if state.text_target != TextTarget::None {
                    let resolved = resolve_reference(&reference).map_err(|message| {
                        SclParseError::at(
                            state.span_at(event_start_off),
                            state.path_str(),
                            ErrorKind::Xml(message),
                        )
                    })?;
                    pending_text.push_explicit(&resolved);
                }
            }
            Event::Eof => {
                flush_text(&mut state, &mut pending_text);
                break;
            }
            // CDATA content is character data written out literally: no
            // unescaping applies inside it, and its edge whitespace is part of
            // the value rather than layout. End-of-line normalization still
            // applies, as it does to any parsed content, so a CRLF-authored
            // file yields a bare newline.
            Event::CData(cdata) if state.text_target != TextTarget::None => {
                pending_text.push_explicit(&cdata.xml10_content());
            }
            _ => {}
        }
        buf.clear();
    }

    // An unclosed element leaves the path stack non-empty at end of input;
    // quick-xml does not check that itself.
    if !state.path.is_empty() {
        let unclosed = state.path.last().cloned().unwrap_or_default();
        let span = state.span_at(reader.buffer_position());
        return Err(SclParseError::at(
            span,
            state.path_str(),
            ErrorKind::Xml(format!(
                "element `<{}>` was still open at end of input",
                unclosed
            )),
        ));
    }

    Ok(result)
}

/// Advances a byte offset to the next `<`, or to the end of the input.
///
/// quick-xml reports the position at the end of the event just read, usually
/// just past a `>`, while the next event may start several whitespace or
/// newline characters later. Advancing keeps the reported line and column on
/// the element's own `<`.
fn advance_to_lt(input: &str, start: u64) -> u64 {
    let bytes = input.as_bytes();
    let len = bytes.len() as u64;
    let mut p = start.min(len);
    while p < len && bytes[p as usize] != b'<' {
        p += 1;
    }
    p
}

/// Extracts the element name from a start tag.
///
/// The reader validates the document's encoding, so the name is already a
/// `str` and the conversion cannot fail.
fn name_of(start: &BytesStart<'_>) -> String {
    start.name().as_ref().to_string()
}

/// Resolves one entity or character reference to its replacement text.
///
/// Only the five predefined XML entities and numeric character references are
/// recognized; an SCL document declaring its own entities is rejected rather
/// than silently losing the text.
///
/// # Errors
///
/// A message naming the reference when it resolves to nothing.
fn resolve_reference(reference: &BytesRef<'_>) -> Result<String, String> {
    match reference.resolve_char_ref() {
        Ok(Some(ch)) => return Ok(ch.to_string()),
        Ok(None) => {}
        Err(e) => return Err(format!("failed to unescape text: {}", e)),
    }
    quick_xml::escape::resolve_predefined_entity(reference.as_ref())
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "failed to unescape text: unknown entity `&{};`",
                reference.as_ref()
            )
        })
}

/// Returns whether a byte is one of the four XML whitespace characters.
///
/// All four are ASCII, so testing bytes never splits a multi-byte character.
fn is_xml_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// One run of character data, with the extent of its explicit fragments.
///
/// An entity or character reference and a CDATA section both spell their
/// content out, so the whitespace they carry belongs to the value. Whitespace
/// is trimmed off the literal text at the two ends of a run and never off such
/// a fragment: `<Val>&#32;A&#32;</Val>` and `<Val><![CDATA[ A ]]></Val>` both
/// yield `" A "`, while `<Val>  A  </Val>` yields `"A"`. Recording where the
/// first and the last explicit fragment land is what separates the two cases.
#[derive(Debug, Default)]
struct TextRun {
    text: String,
    /// Byte offset in `text` at which the first explicit fragment begins.
    first_explicit_start: Option<usize>,
    /// Byte offset in `text` at which the last explicit fragment ends.
    last_explicit_end: Option<usize>,
}

impl TextRun {
    /// Appends literal character data.
    fn push_literal(&mut self, fragment: &str) {
        self.text.push_str(fragment);
    }

    /// Appends a fragment whose whitespace the document states explicitly, the
    /// replacement text of a reference or the content of a CDATA section, and
    /// marks its extent as protected from trimming.
    fn push_explicit(&mut self, fragment: &str) {
        let start = self.text.len();
        self.text.push_str(fragment);
        if self.first_explicit_start.is_none() {
            self.first_explicit_start = Some(start);
        }
        self.last_explicit_end = Some(self.text.len());
    }

    fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Returns the run without the whitespace at its literal ends.
    fn trimmed(&self) -> &str {
        let bytes = self.text.as_bytes();
        // Trimming stops at the first explicit fragment and resumes after the
        // last.
        let guard_start = self.first_explicit_start.unwrap_or(bytes.len());
        let guard_end = self.last_explicit_end.unwrap_or(0);

        let mut start = 0;
        while start < guard_start && is_xml_space(bytes[start]) {
            start += 1;
        }
        let mut end = bytes.len();
        while end > guard_end && end > start && is_xml_space(bytes[end - 1]) {
            end -= 1;
        }
        &self.text[start..end]
    }

    fn clear(&mut self) {
        self.text.clear();
        self.first_explicit_start = None;
        self.last_explicit_end = None;
    }
}

/// Feeds an accumulated run of character data to the active text target.
///
/// A run that holds only literal whitespace is dropped, so indentation between
/// elements never reaches a value.
fn flush_text(state: &mut ParserState<'_>, pending: &mut TextRun) {
    if !pending.is_empty() {
        let trimmed = pending.trimmed();
        if !trimmed.is_empty() {
            handle_text(state, trimmed);
        }
        pending.clear();
    }
}

/// Handles a Start or an Empty event.
///
/// `empty` marks a self-closing `<Foo .../>`. The caller invokes the end
/// handler immediately afterwards, so nothing special is finalized here, while
/// the skip-frame depth still increments and is decremented on end.
fn handle_start(
    state: &mut ParserState<'_>,
    result: &mut RawScl,
    start: &BytesStart<'_>,
    span: SourceSpan,
    _empty: bool,
) -> Result<(), SclParseError> {
    let name = name_of(start);

    // While skipping, the path is still pushed so element_path stays accurate,
    // but no attribute is parsed.
    if state.skip.is_some() {
        state.push_element(&name);
        return Ok(());
    }

    // The path before the push is the parent path, which establishes context.
    let parent_tag = state.path.last().cloned();
    state.push_element(&name);

    match name.as_str() {
        // The SCL root
        "SCL" => {
            // It has to be the outermost element.
            if state.path.len() != 1 {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<SCL>` must be the root element".into()),
                ));
            }
        }
        // Direct children of <SCL> that are skipped with a warning.
        // A real .cid or .scd almost always carries them: <Communication> holds
        // the GSE and SMV publisher addresses, <Substation> the logical node
        // references of the single-line diagram. Neither contributes to the
        // model, so the subtree is skipped and the warning keeps it visible.
        "Substation" | "Communication" => {
            tracing::warn!(
                target: "iec61850_scl::parser",
                element = %name,
                line = span.line,
                col = span.col,
                "skipping the whole `<{}>` subtree; the communication and \
                 substation information it carries does not enter the model",
                name,
            );
            state.enter_skip(name.clone());
        }
        // Direct children of <SCL> that are skipped without a warning.
        "Header" => {
            // Enter skip mode. The subtree is not parsed, but the path is kept
            // so element_path stays accurate.
            state.enter_skip(name.clone());
        }
        // The DataTypeTemplates container
        "DataTypeTemplates" => {
            if parent_tag.as_deref() != Some("SCL") {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml(
                        "`<DataTypeTemplates>` must be a direct child of `<SCL>`".into(),
                    ),
                ));
            }
            // The container has no attributes; its children use the parent tag
            // to establish their context.
        }
        "LNodeType" => {
            if parent_tag.as_deref() != Some("DataTypeTemplates") {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<LNodeType>` must appear inside `<DataTypeTemplates>`".into()),
                ));
            }
            let lnt = build_ln_node_type(start, span, &state.path_str())?;
            // Duplicate identifiers within one table
            if let Some(existing) = result.data_type_templates.ln_node_types.get(&lnt.id) {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::DuplicateIdentifier {
                        element: "LNodeType".to_string(),
                        key: "id".to_string(),
                        value: lnt.id.clone(),
                        first_span: existing.span,
                    },
                ));
            }
            state.cur_lntype = Some(lnt);
        }
        "DOType" => {
            if parent_tag.as_deref() != Some("DataTypeTemplates") {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DOType>` must appear inside `<DataTypeTemplates>`".into()),
                ));
            }
            let dot = build_do_type(start, span, &state.path_str())?;
            if let Some(existing) = result.data_type_templates.do_types.get(&dot.id) {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::DuplicateIdentifier {
                        element: "DOType".to_string(),
                        key: "id".to_string(),
                        value: dot.id.clone(),
                        first_span: existing.span,
                    },
                ));
            }
            state.cur_dotype = Some(dot);
        }
        "DAType" => {
            if parent_tag.as_deref() != Some("DataTypeTemplates") {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DAType>` must appear inside `<DataTypeTemplates>`".into()),
                ));
            }
            let dat = build_da_type(start, span, &state.path_str())?;
            if let Some(existing) = result.data_type_templates.da_types.get(&dat.id) {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::DuplicateIdentifier {
                        element: "DAType".to_string(),
                        key: "id".to_string(),
                        value: dat.id.clone(),
                        first_span: existing.span,
                    },
                ));
            }
            state.cur_datype = Some(dat);
        }
        "EnumType" => {
            if parent_tag.as_deref() != Some("DataTypeTemplates") {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<EnumType>` must appear inside `<DataTypeTemplates>`".into()),
                ));
            }
            let et = build_enum_type(start, span, &state.path_str())?;
            if let Some(existing) = result.data_type_templates.enum_types.get(&et.id) {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::DuplicateIdentifier {
                        element: "EnumType".to_string(),
                        key: "id".to_string(),
                        value: et.id.clone(),
                        first_span: existing.span,
                    },
                ));
            }
            state.cur_enumtype = Some(et);
        }
        // Children inside DataTypeTemplates
        "DO" => {
            // A <DO> is valid only inside an LNodeType.
            if state.cur_lntype.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DO>` must appear inside `<LNodeType>`".into()),
                ));
            }
            let do_def = build_do_def(start, span, &state.path_str())?;
            if let Some(lnt) = state.cur_lntype.as_mut() {
                lnt.dos.push(do_def);
            }
        }
        "SDO" => {
            // An <SDO> is valid only inside a DOType.
            if state.cur_dotype.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<SDO>` must appear inside `<DOType>`".into()),
                ));
            }
            let sdo = build_sdo_def(start, span, &state.path_str())?;
            if let Some(dot) = state.cur_dotype.as_mut() {
                dot.sdos.push(sdo);
            }
        }
        "DA" => {
            // A <DA> is valid only inside a DOType.
            if state.cur_dotype.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DA>` must appear inside `<DOType>`".into()),
                ));
            }
            // A DA already open means a nested DA, which the schema forbids.
            if state.cur_da.is_some() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DA>` cannot nest; use `<BDA>` instead".into()),
                ));
            }
            let da = build_da_def(start, span, &state.path_str())?;
            state.cur_da = Some(da);
        }
        "BDA" => {
            // A BDA appears as a direct child of a DAType, or recursively inside
            // a BDA whose bType is Struct. A DA is deliberately excluded: a DA
            // with bType=Struct references a DAType instead of nesting inline,
            // and its only child element is <Val>.
            if state.cur_datype.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml(
                        "`<BDA>` must appear inside `<DAType>`, possibly nested in another `<BDA>`"
                            .into(),
                    ),
                ));
            }
            let bda = build_bda(start, span, &state.path_str())?;
            state.cur_bda_stack.push(bda);
        }
        "EnumVal" => {
            if state.cur_enumtype.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<EnumVal>` must appear inside `<EnumType>`".into()),
                ));
            }
            // `ord` is required; the name arrives as element text.
            let ord: i32 = parse_required(start.attributes(), "ord", span, &state.path_str())?;
            let desc = optional(start.attributes(), "desc");
            state.cur_enumval = Some(RawEnumValue {
                ord,
                name: String::new(),
                desc,
                span,
            });
            state.text_target = TextTarget::EnumValName;
        }
        "Val" => {
            // A <Val> is valid in two places: under a <DA> or <BDA>, where it is
            // a DataTypeTemplates default value, and under a <DAI>, where it is
            // a runtime override and every setting group slot has to be kept.
            // The sGroup attribute is parsed the same way on both paths.
            let s_group: Option<u32> =
                parse_optional(start.attributes(), "sGroup", span, &state.path_str())?;

            if let Some(dai) = state.cur_dai.as_mut() {
                // A Val under a DAI is a runtime override. An empty entry is
                // pushed first and the following text events accumulate into
                // it, so every setting group survives.
                dai.values.push(RawVal {
                    s_group,
                    raw_text: String::new(),
                    span,
                });
                state.text_target = TextTarget::DaiVal;
            } else if state.cur_da.is_some() || !state.cur_bda_stack.is_empty() {
                // A default value on a DA or a BDA.
                state.text_target = TextTarget::ValDefault { s_group };
            } else {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<Val>` must appear inside `<DA>`, `<BDA>` or `<DAI>`".into()),
                ));
            }
        }
        // The IED chain
        "IED" => {
            if parent_tag.as_deref() != Some("SCL") {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<IED>` must be a direct child of `<SCL>`".into()),
                ));
            }
            let ied = build_ied(start, span, &state.path_str())?;
            // Duplicate name detection
            if let Some(dup) = result.ieds.iter().find(|e| e.name == ied.name) {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::DuplicateIdentifier {
                        element: "IED".to_string(),
                        key: "name".to_string(),
                        value: ied.name.clone(),
                        first_span: dup.span,
                    },
                ));
            }
            state.cur_ied = Some(ied);
        }
        "AccessPoint" => {
            if state.cur_ied.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<AccessPoint>` must appear inside `<IED>`".into()),
                ));
            }
            let ap = build_access_point(start, span, &state.path_str())?;
            // Duplicate name detection within one IED
            if let Some(ied) = state.cur_ied.as_ref() {
                if let Some(dup) = ied.access_points.iter().find(|e| e.name == ap.name) {
                    return Err(SclParseError::at(
                        span,
                        state.path_str(),
                        ErrorKind::DuplicateIdentifier {
                            element: "AccessPoint".to_string(),
                            key: "name".to_string(),
                            value: ap.name.clone(),
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_ap = Some(ap);
        }
        "Server" => {
            if state.cur_ap.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<Server>` must appear inside `<AccessPoint>`".into()),
                ));
            }
            // A Server has no required attribute, and its Authentication child
            // is not parsed.
            state.cur_server = Some(RawServer::default());
        }
        "LDevice" => {
            if state.cur_server.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<LDevice>` must appear inside `<Server>`".into()),
                ));
            }
            let ld = build_ldevice(start, span, &state.path_str())?;
            if let Some(server) = state.cur_server.as_ref() {
                if let Some(dup) = server.logical_devices.iter().find(|e| e.inst == ld.inst) {
                    return Err(SclParseError::at(
                        span,
                        state.path_str(),
                        ErrorKind::DuplicateIdentifier {
                            element: "LDevice".to_string(),
                            key: "inst".to_string(),
                            value: ld.inst.clone(),
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_ld = Some(ld);
        }
        "LN" | "LN0" => {
            if state.cur_ld.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml(format!("`<{}>` must appear inside `<LDevice>`", name)),
                ));
            }
            let ln = build_ln(start, span, &state.path_str(), name == "LN0")?;
            // Duplicate (prefix, lnClass, inst) detection
            let key_prefix = ln.prefix.clone().unwrap_or_default();
            if let Some(ld) = state.cur_ld.as_ref() {
                if let Some(dup) = ld.logical_nodes.iter().find(|e| {
                    e.ln_class == ln.ln_class
                        && e.inst == ln.inst
                        && e.prefix.clone().unwrap_or_default() == key_prefix
                }) {
                    let composed = format!(
                        "{}{}{}",
                        key_prefix.as_str(),
                        ln.ln_class.as_str(),
                        ln.inst.as_str()
                    );
                    return Err(SclParseError::at(
                        span,
                        state.path_str(),
                        ErrorKind::DuplicateIdentifier {
                            element: "LN".to_string(),
                            key: "prefix+lnClass+inst".to_string(),
                            value: composed,
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_ln = Some(ln);
        }
        // Children of a logical node
        "DOI" => {
            // A DOI is valid only directly under an LN or an LN0.
            if state.cur_ln.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DOI>` must appear inside `<LN>` or `<LN0>`".into()),
                ));
            }
            // The schema forbids a nested DOI; its direct children are SDI and DAI.
            if state.cur_doi.is_some() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DOI>` cannot nest".into()),
                ));
            }
            let doi = build_doi(start, span, &state.path_str())?;
            state.cur_doi = Some(doi);
        }
        "SDI" => {
            // An SDI is valid inside a DOI or inside another SDI, so a DOI has
            // to be open.
            if state.cur_doi.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<SDI>` must appear inside `<DOI>` or `<SDI>`".into()),
                ));
            }
            // A DAI is a leaf, so no SDI may open inside one.
            if state.cur_dai.is_some() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<SDI>` cannot appear inside `<DAI>`".into()),
                ));
            }
            let sdi = build_sdi(start, span, &state.path_str())?;
            state.data_instance_stack.push(RawDataInstance::Sdi(sdi));
        }
        "DAI" => {
            // A DAI is valid inside a DOI or an SDI, and is itself a leaf.
            if state.cur_doi.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml("`<DAI>` must appear inside `<DOI>` or `<SDI>`".into()),
                ));
            }
            if state.cur_dai.is_some() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml(
                        "`<DAI>` cannot nest; it is a leaf whose only child is `<Val>`".into(),
                    ),
                ));
            }
            let dai = build_dai(start, span, &state.path_str())?;
            state.cur_dai = Some(dai);
        }
        // Data set and control block children of a logical node.
        // The raw structure is built first, without borrowing the parser state,
        // and only then is the logical node context checked;
        // `require_ln_present` returns a bool rather than a reference, so the
        // caller can take its own mutable borrow.
        "DataSet" => {
            let path = state.path_str();
            require_ln_present(state, span, &name, &path)?;
            let ds = build_data_set(start, span, &path)?;
            // Duplicate data set name within one logical node
            if let Some(ln) = state.cur_ln.as_ref() {
                if let Some(dup) = ln.data_sets.iter().find(|e| e.name == ds.name) {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::DuplicateIdentifier {
                            element: "DataSet".to_string(),
                            key: "name".to_string(),
                            value: ds.name.clone(),
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_data_set = Some(ds);
        }
        "FCDA" => {
            let path = state.path_str();
            // An FCDA is valid only inside a DataSet.
            if state.cur_data_set.is_none() {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::Xml("`<FCDA>` must appear inside `<DataSet>`".into()),
                ));
            }
            let fcda = build_fcda(start, span, &path)?;
            if let Some(ds) = state.cur_data_set.as_mut() {
                ds.fcdas.push(fcda);
            }
        }
        "ReportControl" => {
            let path = state.path_str();
            require_ln_present(state, span, &name, &path)?;
            let rc = build_report_control(start, span, &path)?;
            if let Some(ln) = state.cur_ln.as_ref() {
                if let Some(dup) = ln.report_controls.iter().find(|e| e.name == rc.name) {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::DuplicateIdentifier {
                            element: "ReportControl".to_string(),
                            key: "name".to_string(),
                            value: rc.name.clone(),
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_report_control = Some(rc);
        }
        "LogControl" => {
            let path = state.path_str();
            require_ln_present(state, span, &name, &path)?;
            let lc = build_log_control(start, span, &path)?;
            if let Some(ln) = state.cur_ln.as_ref() {
                if let Some(dup) = ln.log_controls.iter().find(|e| e.name == lc.name) {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::DuplicateIdentifier {
                            element: "LogControl".to_string(),
                            key: "name".to_string(),
                            value: lc.name.clone(),
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_log_control = Some(lc);
        }
        "GSEControl" => {
            let path = state.path_str();
            require_ln_present(state, span, &name, &path)?;
            // Valid only inside an LN0, that is a logical node of class LLN0.
            if !current_ln_is_ln0(state) {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::Xml("`<GSEControl>` must appear inside `<LN0>`".into()),
                ));
            }
            let gse = build_gse_control(start, span, &path)?;
            if let Some(ln) = state.cur_ln.as_ref() {
                if let Some(dup) = ln.gse_controls.iter().find(|e| e.name == gse.name) {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::DuplicateIdentifier {
                            element: "GSEControl".to_string(),
                            key: "name".to_string(),
                            value: gse.name.clone(),
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_gse_control = Some(gse);
        }
        "SampledValueControl" => {
            let path = state.path_str();
            require_ln_present(state, span, &name, &path)?;
            if !current_ln_is_ln0(state) {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::Xml("`<SampledValueControl>` must appear inside `<LN0>`".into()),
                ));
            }
            let svc = build_smv_control(start, span, &path)?;
            if let Some(ln) = state.cur_ln.as_ref() {
                if let Some(dup) = ln.smv_controls.iter().find(|e| e.name == svc.name) {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::DuplicateIdentifier {
                            element: "SampledValueControl".to_string(),
                            key: "name".to_string(),
                            value: svc.name.clone(),
                            first_span: dup.span,
                        },
                    ));
                }
            }
            state.cur_smv_control = Some(svc);
        }
        // Children of a report or log control block: TrgOps, OptFields, SmvOpts
        "TrgOps" => {
            // TrgOps is valid inside a ReportControl or a LogControl.
            let path = state.path_str();
            let bits = crate::enums::parse_trg_ops(start.attributes(), span, &path)?;
            if let Some(rc) = state.cur_report_control.as_mut() {
                rc.trg_ops = bits;
            } else if let Some(lc) = state.cur_log_control.as_mut() {
                lc.trg_ops = bits;
            } else {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::Xml(
                        "`<TrgOps>` must appear inside `<ReportControl>` or `<LogControl>`".into(),
                    ),
                ));
            }
        }
        "OptFields" => {
            let path = state.path_str();
            let bits = crate::enums::parse_opt_fields(start.attributes(), span, &path)?;
            if let Some(rc) = state.cur_report_control.as_mut() {
                rc.opt_fields = bits;
            } else {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::Xml("`<OptFields>` must appear inside `<ReportControl>`".into()),
                ));
            }
        }
        "SmvOpts" => {
            let path = state.path_str();
            let bits = crate::enums::parse_smv_opts(start.attributes(), span, &path)?;
            if let Some(svc) = state.cur_smv_control.as_mut() {
                svc.opts = bits;
            } else {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::Xml("`<SmvOpts>` must appear inside `<SampledValueControl>`".into()),
                ));
            }
        }
        // Still skipped: RptEnabled and Inputs.
        // RptEnabled belongs to service negotiation, where a client limits the
        // number of report instances, and the model does not need it. Inputs
        // belongs to GOOSE subscription, which this parser does not read.
        "SettingControl" => {
            // A SettingControl belongs to the setting groups of IEC 61850-6
            // §9.3.3: it is attached to LN0, at most once per logical node. It
            // carries attributes only, so they are read here and the element is
            // then skipped, which swallows any schema noise below it.
            let path = state.path_str();
            require_ln_present(state, span, &name, &path)?;
            if !current_ln_is_ln0(state) {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::Xml("`<SettingControl>` must appear inside `<LN0>`, since a setting group control block belongs to LLN0".into()),
                ));
            }
            let sgcb = build_setting_control(start, span, &path)?;
            if let Some(ln) = state.cur_ln.as_mut() {
                if ln.setting_control.is_some() {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::Xml(
                            "a logical node may hold at most one `<SettingControl>`".into(),
                        ),
                    ));
                }
                ln.setting_control = Some(sgcb);
            }
            state.enter_skip(name.clone());
        }
        "RptEnabled" | "Inputs" => {
            // The parent has to be plausible, so a broken structure is not let
            // through unnoticed.
            if name == "RptEnabled" {
                if state.cur_report_control.is_none() {
                    return Err(SclParseError::at(
                        span,
                        state.path_str(),
                        ErrorKind::Xml(
                            "`<RptEnabled>` must appear inside `<ReportControl>`".into(),
                        ),
                    ));
                }
            } else if state.cur_ln.is_none() {
                return Err(SclParseError::at(
                    span,
                    state.path_str(),
                    ErrorKind::Xml(format!("`<{}>` must appear inside `<LN>` or `<LN0>`", name)),
                ));
            }
            state.enter_skip(name.clone());
        }
        // Anything else is skipped rather than rejected, until the schema is
        // covered in full.
        _ => {
            state.enter_skip(name.clone());
        }
    }
    Ok(())
}

/// Handles an End event, moving the element being assembled into its parent.
///
/// # Errors
///
/// [`SclParseError`] when the closing tag does not match the open element, or
/// when a required child element is missing.
fn handle_end(
    state: &mut ParserState<'_>,
    result: &mut RawScl,
    name: String,
    span: SourceSpan,
) -> Result<(), SclParseError> {
    // While skipping: leave the skip frame when its root tag closes.
    if state.skip.is_some() {
        let skip_tag = state
            .skip
            .as_ref()
            .map(|(t, _)| t.clone())
            .unwrap_or_default();
        let popped = state.pop_element();
        if popped.as_deref() == Some(skip_tag.as_str()) && state.skip_root_finished() {
            state.skip = None;
        }
        let _ = span;
        return Ok(());
    }

    // A normal end pops the path first.
    let popped = state.pop_element();
    let popped_name = popped.unwrap_or_default();
    if popped_name != name {
        // A path stack mismatch. quick-xml already catches a mismatched closing
        // tag; this is a second guard.
        return Err(SclParseError::at(
            span,
            state.path_str(),
            ErrorKind::Xml(format!(
                "closing tag `</{}>` does not match `{}` on top of the stack",
                name, popped_name
            )),
        ));
    }

    match name.as_str() {
        "SCL" => { /* nothing to do; the root is already assembled */ }
        "IED" => {
            if let Some(ied) = state.cur_ied.take() {
                result.ieds.push(ied);
            }
        }
        "AccessPoint" => {
            if let (Some(ap), Some(ied)) = (state.cur_ap.take(), state.cur_ied.as_mut()) {
                ied.access_points.push(ap);
            }
        }
        "Server" => {
            if let (Some(server), Some(ap)) = (state.cur_server.take(), state.cur_ap.as_mut()) {
                ap.server = Some(server);
            }
        }
        "LDevice" => {
            if let (Some(ld), Some(server)) = (state.cur_ld.take(), state.cur_server.as_mut()) {
                server.logical_devices.push(ld);
            }
        }
        "LN" | "LN0" => {
            if let (Some(ln), Some(ld)) = (state.cur_ln.take(), state.cur_ld.as_mut()) {
                ld.logical_nodes.push(ln);
            }
        }
        // DataTypeTemplates
        "DataTypeTemplates" => { /* the container is done; all four tables are stored */ }
        "LNodeType" => {
            if let Some(lnt) = state.cur_lntype.take() {
                result
                    .data_type_templates
                    .ln_node_types
                    .insert(lnt.id.clone(), lnt);
            }
        }
        "DOType" => {
            if let Some(dot) = state.cur_dotype.take() {
                result
                    .data_type_templates
                    .do_types
                    .insert(dot.id.clone(), dot);
            }
        }
        "DAType" => {
            if let Some(dat) = state.cur_datype.take() {
                result
                    .data_type_templates
                    .da_types
                    .insert(dat.id.clone(), dat);
            }
        }
        "EnumType" => {
            if let Some(et) = state.cur_enumtype.take() {
                result
                    .data_type_templates
                    .enum_types
                    .insert(et.id.clone(), et);
            }
        }
        "DA" => {
            if let (Some(da), Some(dot)) = (state.cur_da.take(), state.cur_dotype.as_mut()) {
                dot.das.push(da);
            }
        }
        "BDA" => {
            // Finish a nested BDA: pop one level and attach it to the parent
            // BDA when there is one, otherwise to the DAType.
            if let Some(bda) = state.cur_bda_stack.pop() {
                if let Some(parent) = state.cur_bda_stack.last_mut() {
                    parent.bda.push(bda);
                } else if let Some(dat) = state.cur_datype.as_mut() {
                    dat.bdas.push(bda);
                }
            }
        }
        "EnumVal" => {
            // Move the finished EnumVal into its EnumType.
            if let (Some(ev), Some(et)) = (state.cur_enumval.take(), state.cur_enumtype.as_mut()) {
                et.values.push(ev);
            }
            state.text_target = TextTarget::None;
        }
        "Val" => {
            // Text accumulation happened on the Text event; only the target is reset.
            state.text_target = TextTarget::None;
        }
        // Logical node children: DOI, SDI, DAI
        "DOI" => {
            // Move the finished DOI into the logical node.
            if let (Some(doi), Some(ln)) = (state.cur_doi.take(), state.cur_ln.as_mut()) {
                ln.doi.push(doi);
            }
        }
        "SDI" => {
            // Pop one SDI level and attach it to the parent SDI, or to the DOI.
            if let Some(top) = state.data_instance_stack.pop() {
                attach_data_instance(state, top);
            }
        }
        "DAI" => {
            // A DAI is a leaf; attach it to the innermost SDI, or to the DOI.
            if let Some(dai) = state.cur_dai.take() {
                attach_data_instance(state, RawDataInstance::Dai(dai));
            }
        }
        // <DO> and <SDO> are attribute-only and self-closing.
        "DO" | "SDO" => { /* nothing to do; already moved into the parent on start */ }
        // Data sets and control blocks
        "DataSet" => {
            if let Some(ds) = state.cur_data_set.take() {
                // The standard requires at least one FCDA. An empty data set is
                // almost always a hand-editing mistake, so it is rejected
                // rather than accepted silently.
                if ds.fcdas.is_empty() {
                    return Err(SclParseError::at(
                        span,
                        state.path_str(),
                        ErrorKind::MissingRequiredElement {
                            name: "FCDA".to_string(),
                        },
                    ));
                }
                if let Some(ln) = state.cur_ln.as_mut() {
                    ln.data_sets.push(ds);
                }
            }
        }
        "FCDA" => { /* attribute-only; already moved into the data set on start */ }
        "ReportControl" => {
            if let (Some(rc), Some(ln)) = (state.cur_report_control.take(), state.cur_ln.as_mut()) {
                ln.report_controls.push(rc);
            }
        }
        "LogControl" => {
            if let (Some(lc), Some(ln)) = (state.cur_log_control.take(), state.cur_ln.as_mut()) {
                ln.log_controls.push(lc);
            }
        }
        "GSEControl" => {
            if let (Some(gse), Some(ln)) = (state.cur_gse_control.take(), state.cur_ln.as_mut()) {
                ln.gse_controls.push(gse);
            }
        }
        "SampledValueControl" => {
            if let (Some(svc), Some(ln)) = (state.cur_smv_control.take(), state.cur_ln.as_mut()) {
                ln.smv_controls.push(svc);
            }
        }
        // TrgOps, OptFields and SmvOpts are attribute-only and were written into
        // their parent on start.
        "TrgOps" | "OptFields" | "SmvOpts" => {}
        _ => {
            // Anything else was taken by the skip handler, so this arm is
            // normally unreachable.
        }
    }
    Ok(())
}

/// Handles a Text event, feeding the raw text into the field the current
/// [`TextTarget`] names.
///
/// # Errors
///
/// [`SclParseError`] when the accumulated text cannot be attached.
fn handle_text(state: &mut ParserState<'_>, raw: &str) {
    match state.text_target.clone() {
        TextTarget::None => {}
        TextTarget::EnumValName => {
            if let Some(ev) = state.cur_enumval.as_mut() {
                // A run arrives already joined. A second run, which a nested
                // element would separate, appends rather than replaces.
                ev.name.push_str(raw);
            }
        }
        TextTarget::ValDefault { s_group } => {
            // The innermost BDA wins; otherwise the text belongs to the DA.
            if let Some(bda) = state.cur_bda_stack.last_mut() {
                if bda.default_value.is_some() {
                    // A DataTypeTemplates default value has no setting group, so
                    // several <Val> elements here contradict the schema: the
                    // last one is kept and a warning is emitted.
                    tracing::warn!(
                        s_group = ?s_group,
                        bda = %bda.name,
                        "several `<Val>` elements on a BDA default value, keeping the last one; a runtime override belongs on a `<DAI>`"
                    );
                }
                bda.default_value = Some(raw.to_string());
            } else if let Some(da) = state.cur_da.as_mut() {
                if da.default_value.is_some() {
                    tracing::warn!(
                        s_group = ?s_group,
                        da = %da.name,
                        "several `<Val>` elements on a DA default value, keeping the last one; a runtime override belongs on a `<DAI>`"
                    );
                }
                da.default_value = Some(raw.to_string());
            }
        }
        TextTarget::DaiVal => {
            // A DAI value accumulates into the entry most recently pushed, so
            // a second run lands in the same slot rather than in a new one.
            if let Some(dai) = state.cur_dai.as_mut() {
                if let Some(v) = dai.values.last_mut() {
                    v.raw_text.push_str(raw);
                }
            }
        }
    }
}

/// Attaches an SDI or a DAI to the innermost open parent: the topmost SDI when
/// one is open, and the current DOI otherwise.
fn attach_data_instance(state: &mut ParserState<'_>, item: RawDataInstance) {
    if let Some(parent) = state.data_instance_stack.last_mut() {
        match parent {
            RawDataInstance::Sdi(sdi) => sdi.children.push(item),
            // A DAI cannot nest; the start handler rejects that, so this arm is
            // unreachable.
            RawDataInstance::Dai(_) => {}
        }
    } else if let Some(doi) = state.cur_doi.as_mut() {
        doi.children.push(item);
    }
}

// ------------------------------------------------------------------------
// Element handlers: attributes into raw structures
// ------------------------------------------------------------------------

/// Parses an `<IED>`: `name` is required; `desc`, `manufacturer` and
/// `configVersion` are optional.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent.
fn build_ied(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawIed, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let desc = optional(start.attributes(), "desc");
    let manufacturer = optional(start.attributes(), "manufacturer");
    let config_version = optional(start.attributes(), "configVersion");
    Ok(RawIed {
        name,
        desc,
        manufacturer,
        config_version,
        access_points: Vec::new(),
        span,
    })
}

/// Parses an `<AccessPoint>`: `name` is required.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent.
fn build_access_point(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawAccessPoint, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    Ok(RawAccessPoint {
        name,
        server: None,
        span,
    })
}

/// Parses an `<LDevice>`: `inst` is required; `ldName` and `desc` are optional.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `inst` is absent.
fn build_ldevice(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawLogicalDevice, SclParseError> {
    let inst = required(start.attributes(), "inst", span, path)?;
    let ld_name = optional(start.attributes(), "ldName");
    let desc = optional(start.attributes(), "desc");
    Ok(RawLogicalDevice {
        inst,
        ld_name,
        desc,
        logical_nodes: Vec::new(),
        span,
    })
}

/// Parses an `<LN>` or an `<LN0>`.
///
/// An `<LN>` requires `lnClass`, `inst` and `lnType`, and accepts `prefix` and
/// `desc`. An `<LN0>` is a logical node of class LLN0, so the class is fixed
/// here while `inst` and `lnType` are still required.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent.
fn build_ln(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
    is_ln0: bool,
) -> Result<RawLogicalNode, SclParseError> {
    let ln_class = if is_ln0 {
        // An LN0 carries no lnClass attribute; the class is fixed to LLN0.
        "LLN0".to_string()
    } else {
        required(start.attributes(), "lnClass", span, path)?
    };
    let inst = required(start.attributes(), "inst", span, path)?;
    let ln_type_ref = required(start.attributes(), "lnType", span, path)?;
    let prefix = optional(start.attributes(), "prefix");
    let desc = optional(start.attributes(), "desc");
    // An LN0 normally has an empty `inst`, but the schema still requires the
    // attribute itself to be present, which this parser enforces.
    let _ = parse_optional::<u32>;
    Ok(RawLogicalNode {
        prefix,
        ln_class,
        inst,
        ln_type_ref,
        desc,
        doi: Vec::new(),
        data_sets: Vec::new(),
        report_controls: Vec::new(),
        log_controls: Vec::new(),
        gse_controls: Vec::new(),
        smv_controls: Vec::new(),
        setting_control: None,
        _inputs: (),
        span,
    })
}

// ------------------------------------------------------------------------
// DataTypeTemplates element handlers
// ------------------------------------------------------------------------

/// Parses an `<LNodeType>`: `id` and `lnClass` are required, `iedType` is
/// optional.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent.
fn build_ln_node_type(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawLNodeType, SclParseError> {
    let id = required(start.attributes(), "id", span, path)?;
    let ln_class = required(start.attributes(), "lnClass", span, path)?;
    let iedtype = optional(start.attributes(), "iedType");
    Ok(RawLNodeType {
        id,
        ln_class,
        iedtype,
        dos: Vec::new(),
        span,
    })
}

/// Parses a `<DO>` inside an `<LNodeType>`: `name` and `type` are required;
/// `transient` and `accessControl` are optional.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent,
/// and [`ErrorKind::AttributeValueInvalid`] when `transient` is not a boolean.
fn build_do_def(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawDoDef, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let do_type_ref = required(start.attributes(), "type", span, path)?;
    let transient =
        parse_optional::<bool>(start.attributes(), "transient", span, path)?.unwrap_or(false);
    let access_control = optional(start.attributes(), "accessControl");
    Ok(RawDoDef {
        name,
        do_type_ref,
        transient,
        access_control,
        span,
    })
}

/// Parses a `<DOType>`: `id` and `cdc` are required.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent.
fn build_do_type(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawDoType, SclParseError> {
    let id = required(start.attributes(), "id", span, path)?;
    let cdc = required(start.attributes(), "cdc", span, path)?;
    Ok(RawDoType {
        id,
        cdc,
        das: Vec::new(),
        sdos: Vec::new(),
        span,
    })
}

/// Parses an `<SDO>` inside a `<DOType>`: `name` and `type` are required.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent.
fn build_sdo_def(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawSdoDef, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let do_type_ref = required(start.attributes(), "type", span, path)?;
    Ok(RawSdoDef {
        name,
        do_type_ref,
        span,
    })
}

/// Parses a `<DA>` inside a `<DOType>`: `name`, `fc` and `bType` are required;
/// `type`, `dchg`, `qchg`, `dupd`, `count` and `valKind` are optional.
///
/// A `<Val>` child is filled in later by the text handler. The functional
/// constraint is validated here but kept as a string, and converted when the
/// model is built.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent,
/// [`ErrorKind::AttributeValueInvalid`] for a malformed value, and
/// [`ErrorKind::EnumValueUnknown`] when `fc` is not a functional constraint.
fn build_da_def(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawDaDef, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let fc_str = required(start.attributes(), "fc", span, path)?;
    // Validate the functional constraint token, then keep the raw string.
    let _ = crate::enums::parse_fc(&fc_str, span, path)?;
    let b_type = required(start.attributes(), "bType", span, path)?;
    let type_ref = optional(start.attributes(), "type");
    let count = parse_optional::<u32>(start.attributes(), "count", span, path)?;
    let val_kind = optional(start.attributes(), "valKind");
    let dchg = parse_optional::<bool>(start.attributes(), "dchg", span, path)?.unwrap_or(false);
    let qchg = parse_optional::<bool>(start.attributes(), "qchg", span, path)?.unwrap_or(false);
    let dupd = parse_optional::<bool>(start.attributes(), "dupd", span, path)?.unwrap_or(false);
    Ok(RawDaDef {
        name,
        fc: fc_str,
        b_type,
        type_ref,
        trg_ops: TriggerOptionsBits {
            data_change: dchg,
            quality_change: qchg,
            data_update: dupd,
            period: false,
            gi: false,
        },
        count,
        default_value: None,
        val_kind,
        bda: Vec::new(),
        span,
    })
}

/// Parses a `<DAType>`: `id` is required.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `id` is absent.
fn build_da_type(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawDaType, SclParseError> {
    let id = required(start.attributes(), "id", span, path)?;
    Ok(RawDaType {
        id,
        bdas: Vec::new(),
        span,
    })
}

/// Parses a `<BDA>` inside a `<DAType>`, possibly nested: `name` and `bType`
/// are required; `type` and `valKind` are optional.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent.
fn build_bda(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawBda, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let b_type = required(start.attributes(), "bType", span, path)?;
    let type_ref = optional(start.attributes(), "type");
    let val_kind = optional(start.attributes(), "valKind");
    Ok(RawBda {
        name,
        b_type,
        type_ref,
        default_value: None,
        val_kind,
        bda: Vec::new(),
        span,
    })
}

/// Parses an `<EnumType>`: `id` is required.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `id` is absent.
fn build_enum_type(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawEnumType, SclParseError> {
    let id = required(start.attributes(), "id", span, path)?;
    Ok(RawEnumType {
        id,
        values: Vec::new(),
        span,
    })
}

// ------------------------------------------------------------------------
// Logical node child handlers: DOI, SDI, DAI
// ------------------------------------------------------------------------

/// Parses a `<DOI>`: `name` is required and `desc` is optional.
///
/// The IEC 61850-6 schema gives a `<DOI>` no `ix` attribute; only `<SDI>` and
/// `<DAI>` carry one. An `ix` on a `<DOI>` is ignored rather than rejected, and
/// it is never taken from the enclosing element.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent.
fn build_doi(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawDoi, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let desc = optional(start.attributes(), "desc");
    // `ix` is ignored deliberately; see the item documentation.
    Ok(RawDoi {
        name,
        desc,
        children: Vec::new(),
        span,
    })
}

/// Parses an `<SDI>`: `name` is required; `ix` and `desc` are optional.
///
/// `ix` is read from this element and never inherited from the enclosing one.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent, and
/// [`ErrorKind::AttributeValueInvalid`] when `ix` is not a `u32`.
fn build_sdi(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawSdi, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let ix = parse_optional::<u32>(start.attributes(), "ix", span, path)?;
    // The schema gives an SDI an informational `desc` that the raw structure
    // does not store; parsing it here only checks that it is well formed.
    Ok(RawSdi {
        name,
        ix,
        children: Vec::new(),
        span,
    })
}

/// Parses a `<DAI>`: `name` is required; `ix`, `valKind` and `valImport` are
/// optional.
///
/// `valImport` is a strict boolean, `"true"` or `"false"`; any other string is
/// rejected rather than treated as false.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent, and
/// [`ErrorKind::AttributeValueInvalid`] for a malformed `ix` or `valImport`.
fn build_dai(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawDai, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let ix = parse_optional::<u32>(start.attributes(), "ix", span, path)?;
    let val_kind = optional(start.attributes(), "valKind");
    let val_import = parse_optional::<bool>(start.attributes(), "valImport", span, path)?;
    Ok(RawDai {
        name,
        ix,
        values: Vec::new(),
        val_kind,
        val_import,
        span,
    })
}

// ------------------------------------------------------------------------
// Data set, FCDA and control block handlers
// ------------------------------------------------------------------------

/// Confirms that a logical node is open.
///
/// Returns a bool rather than a reference, so the caller can take its own
/// borrow. Every logical node child element that appears elsewhere is rejected
/// here.
///
/// # Errors
///
/// [`ErrorKind::Xml`] when no logical node is open.
fn require_ln_present(
    state: &ParserState<'_>,
    span: SourceSpan,
    name: &str,
    path: &str,
) -> Result<(), SclParseError> {
    if state.cur_ln.is_none() {
        return Err(SclParseError::at(
            span,
            path.to_string(),
            ErrorKind::Xml(format!("`<{}>` must appear inside `<LN>` or `<LN0>`", name)),
        ));
    }
    Ok(())
}

/// Reports whether the open logical node is an LN0, that is of class LLN0. The
/// caller has already confirmed that one is open.
fn current_ln_is_ln0(state: &ParserState<'_>) -> bool {
    state
        .cur_ln
        .as_ref()
        .map(|ln| ln.ln_class == "LLN0")
        .unwrap_or(false)
}

/// Parses a `<DataSet>`: `name` is required and `desc` is optional.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent.
fn build_data_set(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawDataSet, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let desc = optional(start.attributes(), "desc");
    Ok(RawDataSet {
        name,
        desc,
        fcdas: Vec::new(),
        span,
    })
}

/// Parses an `<FCDA>`: `ldInst`, `lnClass` and `fc` are required; `prefix`,
/// `lnInst`, `doName`, `daName` and `ix` are optional.
///
/// The functional constraint is validated here but kept as a string, and
/// converted when the model is built.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent,
/// [`ErrorKind::AttributeValueInvalid`] when `ix` is not a `u32`, and
/// [`ErrorKind::EnumValueUnknown`] when `fc` is not a functional constraint.
fn build_fcda(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawFcda, SclParseError> {
    let ld_inst = required(start.attributes(), "ldInst", span, path)?;
    let ln_class = required(start.attributes(), "lnClass", span, path)?;
    let fc_str = required(start.attributes(), "fc", span, path)?;
    // Validate the functional constraint token, then keep the raw string.
    let _ = crate::enums::parse_fc(&fc_str, span, path)?;
    let prefix = optional(start.attributes(), "prefix");
    let ln_inst = optional(start.attributes(), "lnInst");
    let do_name = optional(start.attributes(), "doName");
    let da_name = optional(start.attributes(), "daName");
    let ix = parse_optional::<u32>(start.attributes(), "ix", span, path)?;
    Ok(RawFcda {
        ld_inst,
        prefix,
        ln_class,
        ln_inst,
        do_name,
        da_name,
        fc: fc_str,
        ix,
        span,
    })
}

/// Parses a `<ReportControl>`: `name` is required and the rest is optional
/// with defaults.
///
/// The `<TrgOps>` and `<OptFields>` children are filled in by their own start
/// handlers. When either element is absent, `default_when_missing` supplies the
/// value, so a file that omits it parses instead of failing.
///
/// `<RptEnabled>` is skipped: it belongs to service negotiation, where a client
/// limits the number of report instances, and the model does not need it.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent, and
/// [`ErrorKind::AttributeValueInvalid`] for a malformed numeric or boolean
/// attribute.
fn build_report_control(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawReportControlBlock, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let rpt_id = optional(start.attributes(), "rptID");
    let dat_set = optional(start.attributes(), "datSet");
    let conf_rev = parse_optional::<u32>(start.attributes(), "confRev", span, path)?.unwrap_or(0);
    let buffered =
        parse_optional::<bool>(start.attributes(), "buffered", span, path)?.unwrap_or(false);
    let intg_pd = parse_optional::<u32>(start.attributes(), "intgPd", span, path)?.unwrap_or(0);
    let buf_time = parse_optional::<u32>(start.attributes(), "bufTime", span, path)?.unwrap_or(0);
    let rpt_enabled_max = parse_optional::<u32>(start.attributes(), "rptEnabledMax", span, path)?;
    Ok(RawReportControlBlock {
        name,
        rpt_id,
        dat_set,
        conf_rev,
        buffered,
        intg_pd,
        buf_time,
        // Defaults for a missing <TrgOps> or <OptFields>; a present element
        // overwrites them.
        trg_ops: TriggerOptionsBits::default_when_missing(),
        opt_fields: OptionFieldsBits::default_when_missing(),
        rpt_enabled_max,
        span,
    })
}

/// Parses a `<LogControl>`: `name` is required and the rest is optional with
/// defaults. The `<TrgOps>` child is filled in by its own start handler.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `name` is absent, and
/// [`ErrorKind::AttributeValueInvalid`] for a malformed numeric or boolean
/// attribute.
fn build_log_control(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawLogControl, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let data_set = optional(start.attributes(), "datSet");
    let log_name = optional(start.attributes(), "logName");
    // logEna defaults to true
    let log_ena = parse_optional::<bool>(start.attributes(), "logEna", span, path)?.unwrap_or(true);
    let intg_pd = parse_optional::<u32>(start.attributes(), "intgPd", span, path)?.unwrap_or(0);
    let reason_code =
        parse_optional::<bool>(start.attributes(), "reasonCode", span, path)?.unwrap_or(false);
    let buf_time = parse_optional::<u32>(start.attributes(), "bufTime", span, path)?.unwrap_or(0);
    Ok(RawLogControl {
        name,
        data_set,
        log_name,
        log_ena,
        trg_ops: TriggerOptionsBits::default_when_missing(),
        intg_pd,
        reason_code,
        buf_time,
        span,
    })
}

/// Parses a `<GSEControl>`, valid only inside an LN0: `name`, `appID` and
/// `datSet` are required; `confRev`, `fixedOffs` and `type` are optional.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent,
/// [`ErrorKind::AttributeValueInvalid`] for a malformed value, and
/// [`ErrorKind::EnumValueUnknown`] when `type` is neither GOOSE nor GSSE.
fn build_gse_control(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawGseControl, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let appl_id = required(start.attributes(), "appID", span, path)?;
    let data_set = required(start.attributes(), "datSet", span, path)?;
    let conf_rev = parse_optional::<u32>(start.attributes(), "confRev", span, path)?.unwrap_or(0);
    let fixed_offs =
        parse_optional::<bool>(start.attributes(), "fixedOffs", span, path)?.unwrap_or(false);
    // type defaults to GOOSE
    let gse_type = match optional(start.attributes(), "type") {
        Some(s) => crate::enums::parse_gse_type(&s, span, path)?,
        None => crate::raw::GseControlType::Goose,
    };
    Ok(RawGseControl {
        name,
        appl_id,
        data_set,
        conf_rev,
        fixed_offs,
        gse_type,
        span,
    })
}

/// Parses a `<SampledValueControl>`, valid only inside an LN0: `name`, `smvID`,
/// `datSet`, `smpRate` and `nofASDU` are required; `confRev`, `multicast` and
/// `smpMod` are optional. The `<SmvOpts>` child is filled in by its own start
/// handler.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when a required attribute is absent,
/// [`ErrorKind::AttributeValueInvalid`] for a malformed value, and
/// [`ErrorKind::EnumValueUnknown`] for an unrecognized `smpMod`.
fn build_smv_control(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<RawSampledValueControl, SclParseError> {
    let name = required(start.attributes(), "name", span, path)?;
    let smv_id = required(start.attributes(), "smvID", span, path)?;
    let data_set = required(start.attributes(), "datSet", span, path)?;
    let smp_rate = parse_required::<u32>(start.attributes(), "smpRate", span, path)?;
    let nofasdu = parse_required::<u32>(start.attributes(), "nofASDU", span, path)?;
    let conf_rev = parse_optional::<u32>(start.attributes(), "confRev", span, path)?.unwrap_or(0);
    // multicast defaults to true
    let multicast =
        parse_optional::<bool>(start.attributes(), "multicast", span, path)?.unwrap_or(true);
    let smp_mod = match optional(start.attributes(), "smpMod") {
        Some(s) => crate::enums::parse_smp_mod(&s, span, path)?,
        None => crate::raw::SampledValueSmpMod::SamplesPerPeriod,
    };
    Ok(RawSampledValueControl {
        name,
        smv_id,
        data_set,
        conf_rev,
        multicast,
        smp_rate,
        nofasdu,
        smp_mod,
        opts: SmvOptsBits::default_when_missing(),
        span,
    })
}

/// Parses a `<SettingControl>`, valid only inside an LN0: `numOfSGs` is
/// required, `actSG` defaults to 1, `resvTms` is optional, and `name` and
/// `desc` are SCL bookkeeping that does not reach the model.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when `numOfSGs` is absent, and
/// [`ErrorKind::AttributeValueInvalid`] for a malformed numeric attribute.
fn build_setting_control(
    start: &BytesStart<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<crate::raw::RawSettingControl, SclParseError> {
    let num_of_sgs = parse_required::<u32>(start.attributes(), "numOfSGs", span, path)?;
    let act_sg = parse_optional::<u32>(start.attributes(), "actSG", span, path)?.unwrap_or(1);
    let resv_tms = parse_optional::<u32>(start.attributes(), "resvTms", span, path)?;
    Ok(crate::raw::RawSettingControl {
        num_of_sgs,
        act_sg,
        resv_tms,
        span,
    })
}

// ------------------------------------------------------------------------
// Parser state
// ------------------------------------------------------------------------

/// Parser state: the element path stack, the line tracker, and the chain of
/// elements currently being assembled.
struct ParserState<'a> {
    line_tracker: LineTracker<'a>,
    path: Vec<String>,
    /// The IED being assembled, or `None` outside one.
    cur_ied: Option<RawIed>,
    cur_ap: Option<RawAccessPoint>,
    cur_server: Option<RawServer>,
    cur_ld: Option<RawLogicalDevice>,
    cur_ln: Option<RawLogicalNode>,
    /// Skip mode: the tag that opened the skipped subtree, and the path length
    /// at that moment. A path at least that long is still inside the subtree;
    /// once it shrinks back, skipping ends.
    skip: Option<(String, usize)>,
    // DataTypeTemplates scratch state
    /// The LNodeType being assembled.
    cur_lntype: Option<RawLNodeType>,
    /// The DOType being assembled.
    cur_dotype: Option<RawDoType>,
    /// The DAType being assembled.
    cur_datype: Option<RawDaType>,
    /// The EnumType being assembled.
    cur_enumtype: Option<RawEnumType>,
    /// The DA being assembled inside a DOType. A DA cannot nest.
    cur_da: Option<RawDaDef>,
    /// The stack of nested BDAs. One is pushed on start and popped on end, then
    /// attached to the parent BDA when there is one.
    cur_bda_stack: Vec<RawBda>,
    /// The EnumVal waiting for its text, which is the enumeration name.
    cur_enumval: Option<RawEnumValue>,
    /// Where the next text event goes.
    text_target: TextTarget,
    // Logical node child scratch state
    /// The DOI being assembled inside a logical node.
    cur_doi: Option<RawDoi>,
    /// The DAI being assembled. It is a leaf whose only child is `<Val>`.
    cur_dai: Option<RawDai>,
    /// The stack of nested SDIs, shaped like the BDA stack. One is pushed on
    /// start and popped on end, then attached to the parent SDI or to the DOI.
    /// A DAI is a leaf and is attached directly instead.
    data_instance_stack: Vec<RawDataInstance>,
    // Data set and control block scratch state
    /// The DataSet being assembled inside a logical node.
    cur_data_set: Option<RawDataSet>,
    /// The ReportControl being assembled.
    cur_report_control: Option<RawReportControlBlock>,
    /// The LogControl being assembled.
    cur_log_control: Option<RawLogControl>,
    /// The GSEControl being assembled; valid only on an LN0.
    cur_gse_control: Option<RawGseControl>,
    /// The SampledValueControl being assembled; valid only on an LN0.
    cur_smv_control: Option<RawSampledValueControl>,
}

/// Names the field that the next text event feeds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TextTarget {
    /// No text accumulator is waiting.
    None,
    /// The name of the EnumVal being assembled.
    EnumValName,
    /// The default value of the current DA, or of the innermost BDA.
    ///
    /// A DataTypeTemplates default has no setting group, so `s_group` appears
    /// only in the warning emitted when several values are present.
    ValDefault { s_group: Option<u32> },
    /// The text of the most recently pushed value of the current DAI, one slot
    /// per setting group.
    ///
    /// The setting group was recorded on start, so text accumulation only looks
    /// at the last slot.
    DaiVal,
}

impl<'a> ParserState<'a> {
    fn new(xml: &'a str) -> Self {
        Self {
            line_tracker: LineTracker::new(xml),
            path: Vec::with_capacity(16),
            cur_ied: None,
            cur_ap: None,
            cur_server: None,
            cur_ld: None,
            cur_ln: None,
            skip: None,
            cur_lntype: None,
            cur_dotype: None,
            cur_datype: None,
            cur_enumtype: None,
            cur_da: None,
            cur_bda_stack: Vec::new(),
            cur_enumval: None,
            text_target: TextTarget::None,
            cur_doi: None,
            cur_dai: None,
            data_instance_stack: Vec::new(),
            cur_data_set: None,
            cur_report_control: None,
            cur_log_control: None,
            cur_gse_control: None,
            cur_smv_control: None,
        }
    }

    fn push_element(&mut self, name: &str) {
        self.path.push(name.to_string());
    }

    fn pop_element(&mut self) -> Option<String> {
        self.path.pop()
    }

    fn path_str(&self) -> String {
        self.path.join("/")
    }

    fn span_at(&mut self, byte_offset: u64) -> SourceSpan {
        let (line, col) = self.line_tracker.line_col_at(byte_offset);
        SourceSpan {
            line,
            col,
            byte_offset,
        }
    }

    /// Enters skip mode, recording the path depth of the skipped element.
    ///
    /// Call it after the element has been pushed, so `self.path.len()` is the
    /// depth of the skip root.
    fn enter_skip(&mut self, root_tag: String) {
        let depth = self.path.len();
        self.skip = Some((root_tag, depth));
    }

    /// Leaves skip mode once the path has shrunk back past the skipped element.
    /// Call it after popping.
    fn skip_root_finished(&self) -> bool {
        match self.skip.as_ref() {
            Some((_, entered_depth)) => self.path.len() < *entered_depth,
            None => false,
        }
    }
}

/// Converts a byte offset into a one-based line and column.
///
/// The first call scans the input once to build the table of line starts; every
/// later lookup is a binary search.
struct LineTracker<'a> {
    input: &'a str,
    /// The byte offset of each line start; line 1 starts at 0.
    line_starts: Vec<usize>,
    built: bool,
}

impl<'a> LineTracker<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            line_starts: Vec::new(),
            built: false,
        }
    }

    fn build(&mut self) {
        let mut starts = vec![0usize];
        for (i, b) in self.input.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        self.line_starts = starts;
        self.built = true;
    }

    fn line_col_at(&mut self, byte_offset: u64) -> (u32, u32) {
        if !self.built {
            self.build();
        }
        let off = byte_offset as usize;
        // Binary search for the greatest line start at or below the offset.
        let line_idx = match self.line_starts.binary_search(&off) {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };
        let line_start = self.line_starts.get(line_idx).copied().unwrap_or(0);
        let col = off.saturating_sub(line_start) + 1;
        ((line_idx + 1) as u32, col as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Baseline parser behavior

    #[test]
    fn parses_minimal_empty_scl_root() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
</SCL>
"#;
        let raw = parse(xml).expect("minimal root must parse");
        assert!(raw.ieds.is_empty(), "an empty SCL holds no IED");
    }

    #[test]
    fn malformed_xml_yields_error_with_line_col() {
        // The closing tag is missing on purpose, so the reader reports at EOF.
        let xml = "<SCL><IED name=\"X\">";
        let err = parse(xml).expect_err("malformed XML must err");
        assert!(
            err.span.line >= 1,
            "the message must carry a line number, saw {:?}",
            err.span
        );
    }

    #[test]
    fn line_col_basic() {
        let input = "abc\ndef\nghi";
        let mut t = LineTracker::new(input);
        assert_eq!(t.line_col_at(0), (1, 1)); // 'a'
        assert_eq!(t.line_col_at(2), (1, 3)); // 'c'
        assert_eq!(t.line_col_at(4), (2, 1)); // 'd'
        assert_eq!(t.line_col_at(8), (3, 1)); // 'g'
    }

    // The IED chain handlers

    /// A minimal file: one IED with no access point.
    #[test]
    fn parses_ied_with_no_access_points() {
        let xml = r#"<SCL>
  <IED name="IED1"/>
</SCL>"#;
        let raw = parse(xml).expect("must parse");
        assert_eq!(raw.ieds.len(), 1);
        assert_eq!(raw.ieds[0].name, "IED1");
        assert!(raw.ieds[0].access_points.is_empty());
    }

    /// The full chain, with every attribute of SCL, IED, AccessPoint, Server,
    /// LDevice and LN.
    #[test]
    fn parses_full_main_chain_attributes() {
        let xml = r#"<SCL>
  <IED name="IED1" desc="primary" manufacturer="ACME" configVersion="1.0">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0" ldName="MyLD" desc="ld desc">
          <LN0 inst="" lnType="LLN0_T"/>
          <LN prefix="ANSI" lnClass="MMXU" inst="1" lnType="MMXU_T" desc="meas"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let raw = parse(xml).expect("full chain must parse");

        let ied = &raw.ieds[0];
        assert_eq!(ied.name, "IED1");
        assert_eq!(ied.desc.as_deref(), Some("primary"));
        assert_eq!(ied.manufacturer.as_deref(), Some("ACME"));
        assert_eq!(ied.config_version.as_deref(), Some("1.0"));
        assert_eq!(ied.access_points.len(), 1);

        let ap = &ied.access_points[0];
        assert_eq!(ap.name, "AP1");
        let server = ap.server.as_ref().expect("the Server must be built");
        assert_eq!(server.logical_devices.len(), 1);

        let ld = &server.logical_devices[0];
        assert_eq!(ld.inst, "LD0");
        assert_eq!(ld.ld_name.as_deref(), Some("MyLD"));
        assert_eq!(ld.desc.as_deref(), Some("ld desc"));
        assert_eq!(ld.logical_nodes.len(), 2);

        let ln0 = &ld.logical_nodes[0];
        assert_eq!(ln0.ln_class, "LLN0", "an LN0 fixes lnClass to LLN0");
        assert_eq!(ln0.inst, "");
        assert_eq!(ln0.ln_type_ref, "LLN0_T");

        let mmxu = &ld.logical_nodes[1];
        assert_eq!(mmxu.prefix.as_deref(), Some("ANSI"));
        assert_eq!(mmxu.ln_class, "MMXU");
        assert_eq!(mmxu.inst, "1");
        assert_eq!(mmxu.ln_type_ref, "MMXU_T");
        assert_eq!(mmxu.desc.as_deref(), Some("meas"));
    }

    /// Several IEDs in one file.
    #[test]
    fn parses_multiple_ieds() {
        let xml = r#"<SCL>
  <IED name="IED_A"/>
  <IED name="IED_B"/>
</SCL>"#;
        let raw = parse(xml).expect("must parse");
        assert_eq!(raw.ieds.len(), 2);
        assert_eq!(raw.ieds[0].name, "IED_A");
        assert_eq!(raw.ieds[1].name, "IED_B");
    }

    /// Several logical devices in one IED.
    #[test]
    fn parses_multiple_ldevices() {
        let xml = r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T"/>
        </LDevice>
        <LDevice inst="LD1">
          <LN0 inst="" lnType="LLN0_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let raw = parse(xml).expect("must parse");
        let server = raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .expect("server");
        assert_eq!(server.logical_devices.len(), 2);
        assert_eq!(server.logical_devices[0].inst, "LD0");
        assert_eq!(server.logical_devices[1].inst, "LD1");
    }

    /// Several logical nodes: an LN0 and two ordinary ones, one with a prefix.
    #[test]
    fn parses_ln0_and_multiple_lns() {
        let xml = r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T"/>
          <LN prefix="A" lnClass="MMXU" inst="1" lnType="T1"/>
          <LN prefix="B" lnClass="MMXU" inst="1" lnType="T2"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let raw = parse(xml).expect("must parse");
        let ld = &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .logical_devices[0];
        assert_eq!(ld.logical_nodes.len(), 3);
        assert_eq!(ld.logical_nodes[0].ln_class, "LLN0");
        assert_eq!(ld.logical_nodes[1].prefix.as_deref(), Some("A"));
        assert_eq!(ld.logical_nodes[2].prefix.as_deref(), Some("B"));
        // A different prefix makes two nodes distinct even with the same class
        // and instance.
    }

    /// A missing lnClass yields MissingRequiredAttribute.
    #[test]
    fn missing_ln_class_yields_actionable_err() {
        let xml = r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN inst="1" lnType="T1"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let err = parse(xml).expect_err("must err on missing lnClass");
        assert_eq!(err.attribute.as_deref(), Some("lnClass"));
        match err.kind.as_ref() {
            ErrorKind::MissingRequiredAttribute { name } => assert_eq!(name, "lnClass"),
            other => panic!("expected MissingRequiredAttribute, got {:?}", other),
        }
    }

    /// A duplicate LDevice instance yields DuplicateIdentifier whose first_span
    /// names the right line.
    #[test]
    fn duplicate_ldevice_inst_yields_duplicate_err_with_first_span() {
        let xml = "<SCL>\n  <IED name=\"IED1\">\n    <AccessPoint name=\"AP1\">\n      <Server>\n        <LDevice inst=\"LD0\"><LN0 inst=\"\" lnType=\"T\"/></LDevice>\n        <LDevice inst=\"LD0\"><LN0 inst=\"\" lnType=\"T\"/></LDevice>\n      </Server>\n    </AccessPoint>\n  </IED>\n</SCL>";
        let err = parse(xml).expect_err("duplicate must err");
        match err.kind.as_ref() {
            ErrorKind::DuplicateIdentifier {
                element,
                key,
                value,
                first_span,
            } => {
                assert_eq!(element, "LDevice");
                assert_eq!(key, "inst");
                assert_eq!(value, "LD0");
                // The first LDevice is on line 5.
                assert_eq!(
                    first_span.line, 5,
                    "first_span.line must point at the first LDevice, saw {:?}",
                    first_span
                );
            }
            other => panic!("expected DuplicateIdentifier, got {:?}", other),
        }
    }

    /// The reported line and column are accurate; the fault sits on line 5.
    #[test]
    fn error_span_line_is_accurate() {
        // The faulty element, an LN with no lnClass, inst or lnType, is on line 5.
        let xml = "<SCL>\n  <IED name=\"IED1\">\n    <AccessPoint name=\"AP1\"><Server><LDevice inst=\"LD0\">\n      <LN0 inst=\"\" lnType=\"T\"/>\n      <LN/>\n      </LDevice></Server></AccessPoint>\n  </IED>\n</SCL>";
        let err = parse(xml).expect_err("missing attrs must err");
        assert_eq!(
            err.span.line, 5,
            "the error must point at line 5, saw {:?}",
            err.span
        );
    }

    /// `<Substation>` and `<Communication>` are skipped, so a real `.cid` still
    /// parses. Only the parse result is asserted: the skip also emits a
    /// `tracing::warn!`, which this test does not capture.
    #[test]
    fn substation_and_communication_are_skipped_silently() {
        let xml = r#"<SCL>
  <Header id="H1"/>
  <Substation name="S1">
    <VoltageLevel name="VL1"/>
  </Substation>
  <Communication>
    <SubNetwork name="W1"/>
  </Communication>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server><LDevice inst="LD0">
        <LN0 inst="" lnClass="LLN0" lnType="T"/>
      </LDevice></Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let raw = parse(xml)
            .expect("Substation and Communication must be skipped, leaving the IED parseable");
        assert_eq!(raw.ieds.len(), 1);
        assert_eq!(raw.ieds[0].name, "IED1");
    }

    /// A DataTypeTemplates section and an IED parse together.
    #[test]
    fn data_type_templates_coexists_with_ied() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC"/>
  </DataTypeTemplates>
  <IED name="IED1"/>
</SCL>"#;
        let raw = parse(xml).expect("DataTypeTemplates and IED must parse together");
        assert_eq!(raw.ieds.len(), 1);
        assert_eq!(raw.ieds[0].name, "IED1");
        // DataTypeTemplates is parsed in full.
        assert_eq!(raw.data_type_templates.ln_node_types.len(), 1);
        assert!(raw.data_type_templates.ln_node_types.contains_key("LLN0_T"));
        assert_eq!(raw.data_type_templates.do_types.len(), 1);
    }

    /// A duplicate IED name yields DuplicateIdentifier.
    #[test]
    fn duplicate_ied_name_yields_duplicate_err() {
        let xml = "<SCL>\n  <IED name=\"X\"/>\n  <IED name=\"X\"/>\n</SCL>";
        let err = parse(xml).expect_err("dup IED must err");
        match err.kind.as_ref() {
            ErrorKind::DuplicateIdentifier {
                element,
                value,
                first_span,
                ..
            } => {
                assert_eq!(element, "IED");
                assert_eq!(value, "X");
                assert_eq!(first_span.line, 2);
            }
            other => panic!("expected DuplicateIdentifier, got {:?}", other),
        }
    }

    // DataTypeTemplates handlers

    /// An `<LNodeType>` with several `<DO>` children parses into the right fields.
    #[test]
    fn parses_lnode_type_with_multiple_dos() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0" iedType="MyIED">
      <DO name="Mod" type="ENC_Mod" transient="false"/>
      <DO name="Beh" type="ENS_Beh"/>
      <DO name="Health" type="ENS_Health" accessControl="rw"/>
    </LNodeType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = parse(xml).expect("parse must succeed");
        let lnt = raw
            .data_type_templates
            .ln_node_types
            .get("LLN0_T")
            .expect("LLN0_T present");
        assert_eq!(lnt.ln_class, "LLN0");
        assert_eq!(lnt.iedtype.as_deref(), Some("MyIED"));
        assert_eq!(lnt.dos.len(), 3);
        assert_eq!(lnt.dos[0].name, "Mod");
        assert_eq!(lnt.dos[0].do_type_ref, "ENC_Mod");
        assert!(!lnt.dos[0].transient);
        assert_eq!(lnt.dos[2].name, "Health");
        assert_eq!(lnt.dos[2].access_control.as_deref(), Some("rw"));
    }

    /// A `<DOType>` with several `<DA>` children, an `<SDO>`, and a `<DA>`
    /// carrying a default `<Val>`.
    #[test]
    fn parses_do_type_with_das_sdos_and_val() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DOType id="ENC_Mod" cdc="ENC">
      <DA name="stVal" fc="ST" bType="Enum" type="ModEnum" dchg="true"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModelEnum">
        <Val>status-only</Val>
      </DA>
      <SDO name="origin" type="OrgType"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = parse(xml).expect("parse must succeed");
        let dot = raw
            .data_type_templates
            .do_types
            .get("ENC_Mod")
            .expect("ENC_Mod present");
        assert_eq!(dot.cdc, "ENC");
        assert_eq!(dot.das.len(), 2);
        assert_eq!(dot.das[0].name, "stVal");
        assert_eq!(dot.das[0].fc, "ST");
        assert_eq!(dot.das[0].b_type, "Enum");
        assert_eq!(dot.das[0].type_ref.as_deref(), Some("ModEnum"));
        assert!(dot.das[0].trg_ops.data_change);
        assert_eq!(dot.das[1].name, "ctlModel");
        assert_eq!(dot.das[1].default_value.as_deref(), Some("status-only"));
        assert_eq!(dot.sdos.len(), 1);
        assert_eq!(dot.sdos[0].name, "origin");
        assert_eq!(dot.sdos[0].do_type_ref, "OrgType");
    }

    /// A `<DAType>` with two levels of nested `<BDA>`.
    #[test]
    fn parses_da_type_with_nested_bda() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DAType id="OuterT">
      <BDA name="alpha" bType="Struct" type="InnerT">
        <BDA name="beta" bType="INT32"/>
        <BDA name="gamma" bType="VisString64">
          <Val>hello</Val>
        </BDA>
      </BDA>
      <BDA name="delta" bType="BOOLEAN"/>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = parse(xml).expect("parse must succeed");
        let dat = raw
            .data_type_templates
            .da_types
            .get("OuterT")
            .expect("OuterT present");
        assert_eq!(dat.bdas.len(), 2);
        let alpha = &dat.bdas[0];
        assert_eq!(alpha.name, "alpha");
        assert_eq!(alpha.b_type, "Struct");
        assert_eq!(alpha.type_ref.as_deref(), Some("InnerT"));
        assert_eq!(alpha.bda.len(), 2);
        assert_eq!(alpha.bda[0].name, "beta");
        assert_eq!(alpha.bda[0].b_type, "INT32");
        assert_eq!(alpha.bda[1].name, "gamma");
        assert_eq!(alpha.bda[1].default_value.as_deref(), Some("hello"));
        assert_eq!(dat.bdas[1].name, "delta");
    }

    /// An `<EnumType>` with several `<EnumVal>` children, each with an ord and text.
    #[test]
    fn parses_enum_type_with_values() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <EnumType id="ModEnum">
      <EnumVal ord="1">on</EnumVal>
      <EnumVal ord="2">blocked</EnumVal>
      <EnumVal ord="3" desc="test value">test</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = parse(xml).expect("parse must succeed");
        let et = raw
            .data_type_templates
            .enum_types
            .get("ModEnum")
            .expect("ModEnum present");
        assert_eq!(et.values.len(), 3);
        assert_eq!(et.values[0].ord, 1);
        assert_eq!(et.values[0].name, "on");
        assert_eq!(et.values[1].ord, 2);
        assert_eq!(et.values[1].name, "blocked");
        assert_eq!(et.values[2].ord, 3);
        assert_eq!(et.values[2].name, "test");
        assert_eq!(et.values[2].desc.as_deref(), Some("test value"));
    }

    /// A duplicate LNodeType id yields DuplicateIdentifier with the right first_span.
    #[test]
    fn duplicate_lnode_type_id_yields_err_with_first_span() {
        // The first LNodeType is on line 3.
        let xml = "<SCL>\n  <DataTypeTemplates>\n    <LNodeType id=\"T1\" lnClass=\"LLN0\"/>\n    <LNodeType id=\"T1\" lnClass=\"LPHD\"/>\n  </DataTypeTemplates>\n</SCL>";
        let err = parse(xml).expect_err("duplicate LNodeType id must err");
        match err.kind.as_ref() {
            ErrorKind::DuplicateIdentifier {
                element,
                key,
                value,
                first_span,
            } => {
                assert_eq!(element, "LNodeType");
                assert_eq!(key, "id");
                assert_eq!(value, "T1");
                assert_eq!(
                    first_span.line, 3,
                    "first_span must point at the first LNodeType on line 3, saw {:?}",
                    first_span
                );
            }
            other => panic!("expected DuplicateIdentifier, got {:?}", other),
        }
    }

    /// A `<DA>` without fc yields MissingRequiredAttribute naming fc.
    #[test]
    fn da_missing_fc_yields_err() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" bType="BOOLEAN"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#;
        let err = parse(xml).expect_err("must err on missing fc");
        assert_eq!(err.attribute.as_deref(), Some("fc"));
        match err.kind.as_ref() {
            ErrorKind::MissingRequiredAttribute { name } => assert_eq!(name, "fc"),
            other => panic!("expected MissingRequiredAttribute, got {:?}", other),
        }
    }

    /// A DA with bType Enum and a valid fc keeps the raw string after validation.
    #[test]
    fn da_fc_string_preserved_after_validation() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="MX" bType="FLOAT32"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = parse(xml).expect("parse must succeed");
        let dot = &raw.data_type_templates.do_types["ENC_T"];
        assert_eq!(dot.das[0].fc, "MX");
    }

    /// A duplicate EnumType id yields DuplicateIdentifier.
    #[test]
    fn duplicate_enum_type_id_yields_err() {
        let xml = "<SCL>\n  <DataTypeTemplates>\n    <EnumType id=\"E1\"><EnumVal ord=\"0\">x</EnumVal></EnumType>\n    <EnumType id=\"E1\"><EnumVal ord=\"0\">y</EnumVal></EnumType>\n  </DataTypeTemplates>\n</SCL>";
        let err = parse(xml).expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::DuplicateIdentifier { element, value, .. } => {
                assert_eq!(element, "EnumType");
                assert_eq!(value, "E1");
            }
            other => panic!("expected DuplicateIdentifier, got {:?}", other),
        }
    }

    // Logical node children: DOI, SDI, DAI and Val

    /// Wraps logical node children in a complete LN, LDevice, AccessPoint, IED
    /// and SCL structure.
    fn wrap_in_ln(inner: &str) -> String {
        format!(
            r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN prefix="" lnClass="MMXU" inst="1" lnType="MMXU_T">
{inner}
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#
        )
    }

    fn first_ln(raw: &RawScl) -> &RawLogicalNode {
        &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .expect("server")
            .logical_devices[0]
            .logical_nodes[0]
    }

    /// A simple DOI, DAI and Val path yields the name and the raw text.
    #[test]
    fn parses_doi_with_dai_and_val() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod" desc="mode override">
              <DAI name="ctlModel">
                <Val>status-only</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("parse must succeed");
        let ln = first_ln(&raw);
        assert_eq!(ln.doi.len(), 1);
        let doi = &ln.doi[0];
        assert_eq!(doi.name, "Mod");
        assert_eq!(doi.desc.as_deref(), Some("mode override"));
        assert_eq!(doi.children.len(), 1);
        match &doi.children[0] {
            RawDataInstance::Dai(dai) => {
                assert_eq!(dai.name, "ctlModel");
                assert_eq!(dai.values.len(), 1);
                assert_eq!(dai.values[0].raw_text, "status-only");
                assert_eq!(dai.values[0].s_group, None);
            }
            other => panic!("expected DAI child, got {:?}", other),
        }
    }

    /// Two levels of nested SDI under a DOI produce the right child structure.
    #[test]
    fn parses_doi_with_nested_sdi_two_levels() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Pos">
              <SDI name="origin">
                <SDI name="ctlNum">
                  <DAI name="orCat">
                    <Val>process</Val>
                  </DAI>
                </SDI>
              </SDI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("nested SDI must parse");
        let doi = &first_ln(&raw).doi[0];
        assert_eq!(doi.name, "Pos");
        // The first SDI level
        assert_eq!(doi.children.len(), 1);
        let lvl1 = match &doi.children[0] {
            RawDataInstance::Sdi(s) => s,
            other => panic!("expected SDI at level 1, got {:?}", other),
        };
        assert_eq!(lvl1.name, "origin");
        // The second SDI level
        assert_eq!(lvl1.children.len(), 1);
        let lvl2 = match &lvl1.children[0] {
            RawDataInstance::Sdi(s) => s,
            other => panic!("expected SDI at level 2, got {:?}", other),
        };
        assert_eq!(lvl2.name, "ctlNum");
        // The leaf DAI
        assert_eq!(lvl2.children.len(), 1);
        match &lvl2.children[0] {
            RawDataInstance::Dai(dai) => {
                assert_eq!(dai.name, "orCat");
                assert_eq!(dai.values[0].raw_text, "process");
            }
            other => panic!("expected DAI leaf, got {:?}", other),
        }
    }

    /// A DAI with three `<Val>` elements keeps one slot per setting group, each
    /// matching its sGroup.
    #[test]
    fn parses_dai_with_multiple_val_per_sgroup() {
        let xml = wrap_in_ln(
            r#"            <DOI name="SetPt">
              <DAI name="setMag">
                <Val sGroup="1">10.0</Val>
                <Val sGroup="2">20.5</Val>
                <Val sGroup="3">30.75</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("multi-sGroup must parse");
        let doi = &first_ln(&raw).doi[0];
        let dai = match &doi.children[0] {
            RawDataInstance::Dai(d) => d,
            _ => panic!("expected DAI"),
        };
        assert_eq!(
            dai.values.len(),
            3,
            "all three setting group slots are kept"
        );
        assert_eq!(dai.values[0].s_group, Some(1));
        assert_eq!(dai.values[0].raw_text, "10.0");
        assert_eq!(dai.values[1].s_group, Some(2));
        assert_eq!(dai.values[1].raw_text, "20.5");
        assert_eq!(dai.values[2].s_group, Some(3));
        assert_eq!(dai.values[2].raw_text, "30.75");
    }

    /// A Val without a sGroup attribute yields `None`.
    #[test]
    fn parses_dai_with_single_val_no_sgroup() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="stVal">
                <Val>on</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        let dai = match &first_ln(&raw).doi[0].children[0] {
            RawDataInstance::Dai(d) => d,
            _ => panic!("expected DAI"),
        };
        assert_eq!(dai.values.len(), 1);
        assert_eq!(dai.values[0].s_group, None);
    }

    /// A `<DOI ix="2">` parses without error; the attribute is ignored.
    #[test]
    fn parses_doi_ignores_ix_attribute() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod" ix="2">
              <DAI name="ctlModel">
                <Val>status-only</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("an ix on a DOI must be ignored, not rejected");
        let doi = &first_ln(&raw).doi[0];
        assert_eq!(doi.name, "Mod");
        // The raw structure has no ix field at all.
    }

    /// A DAI ix attribute parses into `Some(u32)`.
    #[test]
    fn dai_in_doi_yields_array_index() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Phs">
              <DAI name="cVal" ix="3">
                <Val>1.23</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        let dai = match &first_ln(&raw).doi[0].children[0] {
            RawDataInstance::Dai(d) => d,
            _ => panic!("expected DAI"),
        };
        assert_eq!(dai.ix, Some(3));
    }

    /// A DOI without name yields MissingRequiredAttribute naming name.
    #[test]
    fn missing_doi_name_yields_actionable_err() {
        let xml = wrap_in_ln(
            r#"            <DOI>
              <DAI name="ctlModel"><Val>x</Val></DAI>
            </DOI>"#,
        );
        let err = parse(&xml).expect_err("missing DOI name must err");
        assert_eq!(err.attribute.as_deref(), Some("name"));
        match err.kind.as_ref() {
            ErrorKind::MissingRequiredAttribute { name } => assert_eq!(name, "name"),
            other => panic!("expected MissingRequiredAttribute, got {:?}", other),
        }
    }

    /// A Val directly under a DOI, outside a DAI, is a structural error.
    #[test]
    fn val_in_non_dai_context_yields_err() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <Val>oops</Val>
            </DOI>"#,
        );
        let err = parse(&xml).expect_err("a Val directly under a DOI must be rejected");
        match err.kind.as_ref() {
            ErrorKind::Xml(msg) => {
                assert!(
                    msg.contains("Val") && (msg.contains("DAI") || msg.contains("DA")),
                    "the message must say a Val belongs inside a DA, BDA or DAI, saw `{}`",
                    msg
                );
            }
            other => panic!("expected Xml structural err, got {:?}", other),
        }
    }

    /// A DAI with valKind and valImport attributes parses them.
    #[test]
    fn parses_dai_val_kind_and_val_import() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel" valKind="RO" valImport="true">
                <Val>status-only</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        let dai = match &first_ln(&raw).doi[0].children[0] {
            RawDataInstance::Dai(d) => d,
            _ => panic!("expected DAI"),
        };
        assert_eq!(dai.val_kind.as_deref(), Some("RO"));
        assert_eq!(dai.val_import, Some(true));
    }

    /// Returns the DAI that `wrap_in_ln` places under the first `<DOI>`.
    fn dai_of(raw: &RawScl) -> &RawDai {
        match &first_ln(raw).doi[0].children[0] {
            RawDataInstance::Dai(d) => d,
            _ => panic!("expected DAI"),
        }
    }

    /// Entity and character references inside a `<Val>` rejoin the surrounding
    /// text, and the whitespace around the whole run is trimmed.
    #[test]
    fn dai_val_text_resolves_references_and_keeps_inner_spacing() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val>  A &amp; B &lt;C&gt; &#65;&#x42;  </Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        let dai = match &first_ln(&raw).doi[0].children[0] {
            RawDataInstance::Dai(d) => d,
            _ => panic!("expected DAI"),
        };
        assert_eq!(dai.values[0].raw_text, "A & B <C> AB");
    }

    /// Whitespace written as a character reference is part of the value: the
    /// reader trims the literal text at the ends of a run, never a replacement.
    #[test]
    fn dai_val_char_ref_whitespace_survives_trimming() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val>&#32;A&#32;</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        assert_eq!(dai_of(&raw).values[0].raw_text, " A ");
    }

    /// A run whose only content is a character reference to a space keeps that
    /// space, while a run of literal whitespace is dropped.
    #[test]
    fn dai_val_lone_char_ref_space_is_kept() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val>&#32;</Val>
                <Val>   </Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        let dai = dai_of(&raw);
        assert_eq!(dai.values[0].raw_text, " ");
        assert_eq!(dai.values[1].raw_text, "");
    }

    /// Literal whitespace outside a reference is still trimmed, and only up to
    /// the reference.
    #[test]
    fn dai_val_literal_edges_trim_up_to_the_reference() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val>  &#32;A&#32;  </Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        assert_eq!(dai_of(&raw).values[0].raw_text, " A ");
    }

    /// A CDATA section reaches the value verbatim: nothing inside it is
    /// unescaped, and the whitespace at its ends is part of the value.
    #[test]
    fn dai_val_cdata_content_is_kept_verbatim() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val><![CDATA[ A & B ]]></Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        assert_eq!(dai_of(&raw).values[0].raw_text, " A & B ");
    }

    /// Literal text and a CDATA section in the same run join in document
    /// order, and the spacing the section carries between them survives.
    #[test]
    fn dai_val_mixed_literal_and_cdata_keeps_interior_spacing() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val>x<![CDATA[ y ]]>z</Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        assert_eq!(dai_of(&raw).values[0].raw_text, "x y z");
    }

    /// End-of-line normalization reaches inside a CDATA section as it does any
    /// other parsed content: a CRLF-authored file yields a bare newline, and so
    /// does a lone carriage return.
    #[test]
    fn dai_val_cdata_line_ends_are_normalized() {
        let body = format!(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val><![CDATA[A{}B{}C]]></Val>
              </DAI>
            </DOI>"#,
            "\r\n", "\r"
        );
        let raw = parse(&wrap_in_ln(&body)).expect("must parse");
        assert_eq!(dai_of(&raw).values[0].raw_text, "A\nB\nC");
    }

    /// A run whose only content is a CDATA section of whitespace keeps that
    /// whitespace, while a run of literal whitespace is dropped.
    #[test]
    fn dai_val_cdata_whitespace_only_is_kept() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val><![CDATA[   ]]></Val>
                <Val>   </Val>
              </DAI>
            </DOI>"#,
        );
        let raw = parse(&xml).expect("must parse");
        let dai = dai_of(&raw);
        assert_eq!(dai.values[0].raw_text, "   ");
        assert_eq!(dai.values[1].raw_text, "");
    }

    /// A `<Val>` default on a DA carries a split run in full: the target on
    /// that path assigns rather than appends, so a lost fragment would be
    /// silent.
    #[test]
    fn da_default_val_keeps_every_fragment_of_a_split_run() {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <DataTypeTemplates>
    <DAType id="DAT1">
      <BDA name="setVal" bType="VisString255">
        <Val>{}</Val>
      </BDA>
    </DAType>
  </DataTypeTemplates>
</SCL>"#,
            "  A &amp; B&#32;"
        );
        let raw = parse(&xml).expect("must parse");
        let bda = &raw.data_type_templates.da_types["DAT1"].bdas[0];
        assert_eq!(bda.default_value.as_deref(), Some("A & B "));
    }

    /// A `<Val>` default on a DA takes a run mixing literal text and a CDATA
    /// section in full: the target on that path assigns rather than appends,
    /// so a lost fragment would be silent.
    #[test]
    fn da_default_val_keeps_cdata_content() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <DataTypeTemplates>
    <DAType id="DAT1">
      <BDA name="setVal" bType="VisString255">
        <Val>x<![CDATA[ & ]]>z</Val>
      </BDA>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = parse(xml).expect("must parse");
        let bda = &raw.data_type_templates.da_types["DAT1"].bdas[0];
        assert_eq!(bda.default_value.as_deref(), Some("x & z"));
    }

    /// A reference that is neither predefined nor numeric is reported rather
    /// than dropped from the value.
    #[test]
    fn dai_val_unknown_entity_yields_err() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="ctlModel">
                <Val>a&nbsp;b</Val>
              </DAI>
            </DOI>"#,
        );
        let err = parse(&xml).expect_err("an undeclared entity must be rejected");
        match err.kind.as_ref() {
            ErrorKind::Xml(msg) => assert!(
                msg.contains("nbsp"),
                "the message must name the unresolved entity, saw `{}`",
                msg
            ),
            other => panic!("expected Xml err, got {:?}", other),
        }
    }

    /// A DAI inside another DAI is rejected.
    #[test]
    fn nested_dai_yields_err() {
        let xml = wrap_in_ln(
            r#"            <DOI name="Mod">
              <DAI name="outer">
                <DAI name="inner"><Val>x</Val></DAI>
              </DAI>
            </DOI>"#,
        );
        let err = parse(&xml).expect_err("nested DAI must err");
        match err.kind.as_ref() {
            ErrorKind::Xml(msg) => assert!(
                msg.contains("DAI"),
                "the message must say a DAI cannot nest, saw `{}`",
                msg
            ),
            other => panic!("expected Xml err, got {:?}", other),
        }
    }

    // Data set, FCDA and control blocks

    /// Wraps a node in an LN0, since GSEControl and SampledValueControl are
    /// valid only there.
    fn wrap_in_ln0(inner: &str) -> String {
        format!(
            r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
{inner}
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#
        )
    }

    /// A DataSet with several FCDA children keeps them in order.
    #[test]
    fn parses_dataset_with_fcdas() {
        let xml = wrap_in_ln(
            r#"            <DataSet name="DS1" desc="reporting set">
              <FCDA ldInst="LD0" prefix="" lnClass="MMXU" lnInst="1" doName="A.phsA.cVal" daName="mag" fc="MX"/>
              <FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" doName="A.phsB" fc="MX"/>
              <FCDA ldInst="LD0" lnClass="LLN0" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>"#,
        );
        let raw = parse(&xml).expect("DataSet must parse");
        let ln = first_ln(&raw);
        assert_eq!(ln.data_sets.len(), 1);
        let ds = &ln.data_sets[0];
        assert_eq!(ds.name, "DS1");
        assert_eq!(ds.desc.as_deref(), Some("reporting set"));
        assert_eq!(ds.fcdas.len(), 3, "all three FCDA entries are kept");
        // The order is significant on the wire.
        assert_eq!(ds.fcdas[0].do_name.as_deref(), Some("A.phsA.cVal"));
        assert_eq!(ds.fcdas[1].do_name.as_deref(), Some("A.phsB"));
        assert_eq!(ds.fcdas[2].do_name.as_deref(), Some("Mod"));
    }

    /// Every FCDA attribute is read.
    #[test]
    fn parses_fcda_full_attributes() {
        let xml = wrap_in_ln(
            r#"            <DataSet name="DS1">
              <FCDA ldInst="LD1" prefix="ANSI" lnClass="MMXU" lnInst="2" doName="A.phsA" daName="cVal.mag.f" fc="MX" ix="3"/>
            </DataSet>"#,
        );
        let raw = parse(&xml).expect("FCDA must parse");
        let fcda = &first_ln(&raw).data_sets[0].fcdas[0];
        assert_eq!(fcda.ld_inst, "LD1");
        assert_eq!(fcda.prefix.as_deref(), Some("ANSI"));
        assert_eq!(fcda.ln_class, "MMXU");
        assert_eq!(fcda.ln_inst.as_deref(), Some("2"));
        assert_eq!(fcda.do_name.as_deref(), Some("A.phsA"));
        assert_eq!(fcda.da_name.as_deref(), Some("cVal.mag.f"));
        assert_eq!(fcda.fc, "MX");
        assert_eq!(fcda.ix, Some(3));
    }

    /// A DataSet with no FCDA yields MissingRequiredElement, detected on end.
    #[test]
    fn dataset_with_zero_fcda_yields_err() {
        let xml = wrap_in_ln(r#"            <DataSet name="Empty"></DataSet>"#);
        let err = parse(&xml).expect_err("empty DataSet must err");
        match err.kind.as_ref() {
            ErrorKind::MissingRequiredElement { name } => assert_eq!(name, "FCDA"),
            other => panic!("expected MissingRequiredElement(FCDA), got {:?}", other),
        }
    }

    /// A ReportControl with TrgOps and OptFields.
    #[test]
    fn parses_report_control_basic() {
        let xml = wrap_in_ln(
            r#"            <ReportControl name="RC1" rptID="MyRpt" datSet="DS1" confRev="42" buffered="false" intgPd="1000" bufTime="50">
              <TrgOps dchg="true" qchg="true" period="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true"/>
            </ReportControl>"#,
        );
        let raw = parse(&xml).expect("ReportControl must parse");
        let rc = &first_ln(&raw).report_controls[0];
        assert_eq!(rc.name, "RC1");
        assert_eq!(rc.rpt_id.as_deref(), Some("MyRpt"));
        assert_eq!(rc.dat_set.as_deref(), Some("DS1"));
        assert_eq!(rc.conf_rev, 42);
        assert!(!rc.buffered);
        assert_eq!(rc.intg_pd, 1000);
        assert_eq!(rc.buf_time, 50);
        assert!(rc.trg_ops.data_change && rc.trg_ops.quality_change && rc.trg_ops.period);
        assert!(!rc.trg_ops.data_update);
        assert!(rc.opt_fields.seq_num && rc.opt_fields.time_stamp && rc.opt_fields.data_set);
        // bufOvfl defaults to true, as does the fallback for a missing OptFields.
        assert!(rc.opt_fields.buffer_overflow);
    }

    /// Missing confRev, bufTime, TrgOps and OptFields fall back to the defaults.
    #[test]
    fn parses_report_control_default_values() {
        let xml = wrap_in_ln(r#"            <ReportControl name="RC2"/>"#);
        let raw = parse(&xml).expect("RC with all defaults must parse");
        let rc = &first_ln(&raw).report_controls[0];
        assert_eq!(rc.conf_rev, 0);
        assert!(!rc.buffered);
        assert_eq!(rc.intg_pd, 0);
        assert_eq!(rc.buf_time, 0);
        // A missing <TrgOps> leaves every bit clear.
        assert!(!rc.trg_ops.gi);
        assert!(!rc.trg_ops.data_change);
        // A missing <OptFields> leaves bufOvfl true and everything else false.
        assert!(rc.opt_fields.buffer_overflow);
        assert!(!rc.opt_fields.seq_num);
    }

    /// buffered="true" is read.
    #[test]
    fn parses_report_control_buffered_true() {
        let xml = wrap_in_ln(r#"            <ReportControl name="BRC" buffered="true"/>"#);
        let raw = parse(&xml).expect("buffered RC must parse");
        let rc = &first_ln(&raw).report_controls[0];
        assert!(rc.buffered);
    }

    /// A LogControl with TrgOps.
    #[test]
    fn parses_log_control_basic() {
        let xml = wrap_in_ln(
            r#"            <LogControl name="LC1" datSet="DS1" logName="myLog" intgPd="500" reasonCode="true" bufTime="20">
              <TrgOps dchg="true"/>
            </LogControl>"#,
        );
        let raw = parse(&xml).expect("LogControl must parse");
        let lc = &first_ln(&raw).log_controls[0];
        assert_eq!(lc.name, "LC1");
        assert_eq!(lc.data_set.as_deref(), Some("DS1"));
        assert_eq!(lc.log_name.as_deref(), Some("myLog"));
        // logEna defaults to true when the attribute is absent.
        assert!(lc.log_ena);
        assert_eq!(lc.intg_pd, 500);
        assert!(lc.reason_code);
        assert_eq!(lc.buf_time, 20);
        assert!(lc.trg_ops.data_change);
    }

    /// A complete GSEControl inside an LN0.
    #[test]
    fn parses_gse_control_in_ln0() {
        let xml = wrap_in_ln0(
            r#"            <GSEControl name="gse1" appID="AP1" datSet="DS1" confRev="3" fixedOffs="true" type="GOOSE"/>"#,
        );
        let raw = parse(&xml).expect("GSEControl in LN0 must parse");
        let ln0 = &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .logical_devices[0]
            .logical_nodes[0];
        assert_eq!(ln0.ln_class, "LLN0");
        let gse = &ln0.gse_controls[0];
        assert_eq!(gse.name, "gse1");
        assert_eq!(gse.appl_id, "AP1");
        assert_eq!(gse.data_set, "DS1");
        assert_eq!(gse.conf_rev, 3);
        assert!(gse.fixed_offs);
        assert_eq!(gse.gse_type, crate::raw::GseControlType::Goose);
    }

    /// A GSEControl inside an ordinary logical node is a structural error.
    #[test]
    fn gse_control_outside_ln0_yields_err() {
        let xml = wrap_in_ln(r#"            <GSEControl name="gse1" appID="AP1" datSet="DS1"/>"#);
        let err = parse(&xml).expect_err("a GSEControl outside an LN0 must be rejected");
        match err.kind.as_ref() {
            ErrorKind::Xml(msg) => assert!(
                msg.contains("GSEControl") && msg.contains("LN0"),
                "the message must say a GSEControl belongs inside an LN0, saw `{}`",
                msg
            ),
            other => panic!("expected Xml structural err, got {:?}", other),
        }
    }

    /// A complete SampledValueControl with SmvOpts.
    #[test]
    fn parses_sampled_value_control() {
        let xml = wrap_in_ln0(
            r#"            <SampledValueControl name="svc1" smvID="MySV" datSet="DS1" smpRate="4000" nofASDU="1" confRev="2" multicast="true" smpMod="SmpPerPeriod">
              <SmvOpts refreshTime="true" sampleSynchronized="true" sampleRate="true"/>
            </SampledValueControl>"#,
        );
        let raw = parse(&xml).expect("SVC must parse");
        let ln0 = &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .logical_devices[0]
            .logical_nodes[0];
        let svc = &ln0.smv_controls[0];
        assert_eq!(svc.name, "svc1");
        assert_eq!(svc.smv_id, "MySV");
        assert_eq!(svc.data_set, "DS1");
        assert_eq!(svc.smp_rate, 4000);
        assert_eq!(svc.nofasdu, 1);
        assert_eq!(svc.conf_rev, 2);
        assert!(svc.multicast);
        assert_eq!(
            svc.smp_mod,
            crate::raw::SampledValueSmpMod::SamplesPerPeriod
        );
        assert!(svc.opts.refresh_time && svc.opts.sample_synchronized && svc.opts.sample_rate);
    }

    /// A missing smpMod falls back to samples per period.
    #[test]
    fn parses_smp_mod_default_smp_per_period() {
        let xml = wrap_in_ln0(
            r#"            <SampledValueControl name="svc2" smvID="X" datSet="DS1" smpRate="80" nofASDU="1"/>"#,
        );
        let raw = parse(&xml).expect("SVC w/o smpMod must parse");
        let ln0 = &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .logical_devices[0]
            .logical_nodes[0];
        let svc = &ln0.smv_controls[0];
        assert_eq!(
            svc.smp_mod,
            crate::raw::SampledValueSmpMod::SamplesPerPeriod
        );
        // multicast defaults to true and confRev to 0.
        assert!(svc.multicast);
        assert_eq!(svc.conf_rev, 0);
    }

    /// A duplicate DataSet name yields DuplicateIdentifier.
    #[test]
    fn duplicate_dataset_name_yields_err() {
        let xml = wrap_in_ln(
            r#"            <DataSet name="DS1">
              <FCDA ldInst="LD0" lnClass="MMXU" fc="MX"/>
            </DataSet>
            <DataSet name="DS1">
              <FCDA ldInst="LD0" lnClass="MMXU" fc="MX"/>
            </DataSet>"#,
        );
        let err = parse(&xml).expect_err("duplicate DataSet name must err");
        match err.kind.as_ref() {
            ErrorKind::DuplicateIdentifier { element, value, .. } => {
                assert_eq!(element, "DataSet");
                assert_eq!(value, "DS1");
            }
            other => panic!("expected DuplicateIdentifier, got {:?}", other),
        }
    }

    /// A GSEControl with no type falls back to GOOSE.
    #[test]
    fn gse_control_default_type_is_goose() {
        let xml =
            wrap_in_ln0(r#"            <GSEControl name="gseDefault" appID="AP1" datSet="DS1"/>"#);
        let raw = parse(&xml).expect("GSEControl w/o type must parse");
        let ln0 = &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .logical_devices[0]
            .logical_nodes[0];
        let gse = &ln0.gse_controls[0];
        assert_eq!(gse.gse_type, crate::raw::GseControlType::Goose);
        assert_eq!(gse.conf_rev, 0);
        assert!(!gse.fixed_offs);
    }

    #[test]
    fn parses_setting_control_basic() {
        let xml = wrap_in_ln0(
            r#"            <SettingControl name="sg" numOfSGs="4" actSG="2" resvTms="45"/>"#,
        );
        let raw = parse(&xml).expect("SettingControl must parse");
        let ln0 = &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .logical_devices[0]
            .logical_nodes[0];
        let sgcb = ln0
            .setting_control
            .as_ref()
            .expect("setting_control should be populated");
        assert_eq!(sgcb.num_of_sgs, 4);
        assert_eq!(sgcb.act_sg, 2);
        assert_eq!(sgcb.resv_tms, Some(45));
    }

    #[test]
    fn parses_setting_control_defaults_actsg_to_one_and_omits_resvtms() {
        let xml = wrap_in_ln0(r#"            <SettingControl numOfSGs="2"/>"#);
        let raw = parse(&xml).expect("SettingControl w/o actSG/resvTms must parse");
        let ln0 = &raw.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .logical_devices[0]
            .logical_nodes[0];
        let sgcb = ln0.setting_control.as_ref().expect("present");
        assert_eq!(sgcb.num_of_sgs, 2);
        assert_eq!(
            sgcb.act_sg, 1,
            "actSG missing, so it defaults to 1 per IEC 61850-6"
        );
        assert!(sgcb.resv_tms.is_none());
    }

    #[test]
    fn setting_control_in_non_ln0_yields_err() {
        // A SettingControl is valid only on an LN0; on an ordinary node it must
        // be rejected rather than skipped.
        let xml = wrap_in_ln(r#"            <SettingControl numOfSGs="3"/>"#);
        let err = parse(&xml).expect_err("SettingControl outside LN0 must err");
        match err.kind.as_ref() {
            ErrorKind::Xml(msg) => assert!(msg.contains("LN0"), "got: {msg}"),
            other => panic!("expected Xml error, got {:?}", other),
        }
    }

    #[test]
    fn duplicate_setting_control_yields_err() {
        let xml = wrap_in_ln0(
            r#"            <SettingControl numOfSGs="2"/>
            <SettingControl numOfSGs="3"/>"#,
        );
        let err = parse(&xml).expect_err("second SettingControl must err");
        match err.kind.as_ref() {
            ErrorKind::Xml(msg) => {
                assert!(msg.to_lowercase().contains("at most"))
            }
            other => panic!("expected Xml error, got {:?}", other),
        }
    }
}
