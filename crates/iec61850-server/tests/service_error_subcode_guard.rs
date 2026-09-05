//! Scans the workspace sources for `ErrorClass::Access(...)` and holds every
//! subcode inside the range the ISO 9506-2 `access [7]` alternative defines,
//! `other(0)` through `object-invalidated(4)`.
//!
//! The `DataAccessError` codes reach 11 and share the numeric space without
//! sharing the meaning, so a code copied from there travels on the wire as a
//! different error. A scan over the sources catches that for handlers that do
//! not exist yet, which a per-handler test cannot do.
//!
//! `ErrorClass::Access(...)` also appears as a destructuring pattern, whose
//! argument binds a name instead of naming a subcode. A binding is accepted
//! only in the file that defines the enum; anywhere else the argument must be
//! a literal in range or a named subcode, so that a subcode reaching the wire
//! is always one this scan has checked.

use std::fs;
use std::path::{Path, PathBuf};

/// Highest subcode the `access [7]` alternative defines.
const MAX_ACCESS_SUBCODE: u32 = 4;

/// Every `ErrorClass::Access(...)` occurrence starts with this text.
const SITE_PREFIX: &str = "ErrorClass::Access(";

/// Named subcodes accepted as the argument of an `access [7]` construction,
/// with or without a module prefix.
const ACCEPTED_NAMES: &[&str] = &[
    "access::OTHER",
    "access::OBJECT_ACCESS_UNSUPPORTED",
    "access::OBJECT_NON_EXISTENT",
    "access::OBJECT_ACCESS_DENIED",
    "access::OBJECT_INVALIDATED",
];

/// The file that defines `ErrorClass`, and the only file where the alternative
/// may be destructured.
const DEFINITION_FILE: &str = "service_error.rs";

/// What the argument of one `ErrorClass::Access(...)` occurrence is.
#[derive(Debug, PartialEq, Eq)]
enum Argument {
    /// A decimal literal inside the range of the alternative.
    LiteralInRange,
    /// A decimal literal outside the range of the alternative.
    LiteralOutOfRange,
    /// One of the named subcodes of the alternative.
    NamedSubcode,
    /// A wildcard or a binding, which is a destructuring pattern.
    Binding,
    /// Anything else, whose value this scan cannot check.
    Unchecked,
}

/// Classifies the argument text of one occurrence.
fn classify(argument: &str) -> Argument {
    if let Ok(n) = argument.parse::<u32>() {
        return if n <= MAX_ACCESS_SUBCODE {
            Argument::LiteralInRange
        } else {
            Argument::LiteralOutOfRange
        };
    }
    if ACCEPTED_NAMES
        .iter()
        .any(|name| argument == *name || argument.ends_with(&format!("::{name}")))
    {
        return Argument::NamedSubcode;
    }
    // a wildcard or a lower snake case identifier binds, it does not name a subcode
    let binds = argument == "_"
        || (!argument.is_empty()
            && argument
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
    if binds {
        Argument::Binding
    } else {
        Argument::Unchecked
    }
}

/// The argument text of every `ErrorClass::Access(...)` occurrence in `src`.
fn arguments(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(idx) = rest.find(SITE_PREFIX) {
        let after = &rest[idx + SITE_PREFIX.len()..];
        let end = match after.find(')') {
            Some(e) => e,
            None => break,
        };
        out.push(after[..end].trim().to_string());
        rest = &after[end..];
    }
    out
}

/// Composes one `ErrorClass::Access(...)` occurrence around `argument`.
///
/// The samples are composed rather than written out so that a repository-wide
/// search for an out-of-range subcode finds no line of this file.
fn sample(argument: &str) -> String {
    format!("{SITE_PREFIX}{argument})")
}

/// Reports every occurrence in `path` whose subcode is not one this scan
/// accepts. `path` decides whether a destructuring pattern is allowed.
fn violations(path: &str, src: &str) -> Vec<String> {
    let is_definition = path.replace('\\', "/").ends_with(DEFINITION_FILE);
    let mut out = Vec::new();
    for argument in arguments(src) {
        let reason = match classify(&argument) {
            Argument::LiteralInRange | Argument::NamedSubcode => continue,
            Argument::Binding if is_definition => continue,
            Argument::Binding => "destructured outside the file that defines the enum",
            Argument::LiteralOutOfRange => "outside the range of the access alternative",
            Argument::Unchecked => "not a literal in range and not a named subcode",
        };
        out.push(format!(
            "{path}: ErrorClass::Access({argument}) is {reason}"
        ));
    }
    out
}

/// Every `.rs` file under the workspace `crates` directory, except this file,
/// whose sample strings are deliberately out of range.
fn workspace_sources() -> Vec<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the server crate sits inside the crates directory")
        .to_path_buf();
    let this_file = Path::new(file!())
        .file_name()
        .expect("the test file has a name")
        .to_owned();

    let mut out = Vec::new();
    let mut stack = vec![crates_dir];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // build output holds generated copies of the sources
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name() != Some(this_file.as_os_str())
            {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn access_subcodes_in_the_workspace_are_within_the_iso_range() {
    let files = workspace_sources();
    assert!(
        files.len() > 100,
        "the source scan found only {} files, so it is not reaching the workspace",
        files.len()
    );

    let mut occurrences = 0usize;
    let mut named = 0usize;
    let mut found: Vec<String> = Vec::new();
    for path in &files {
        let src = fs::read_to_string(path).unwrap_or_default();
        for argument in arguments(&src) {
            occurrences += 1;
            if classify(&argument) == Argument::NamedSubcode {
                named += 1;
            }
        }
        found.extend(violations(&path.display().to_string(), &src));
    }

    assert!(
        occurrences >= 10,
        "the scan found {occurrences} occurrences, too few to be reading the handlers"
    );
    assert!(
        named >= 10,
        "the scan found {named} named subcodes, so the handlers are still writing bare numbers"
    );
    assert!(
        found.is_empty(),
        "the access alternative defines subcodes 0 through {MAX_ACCESS_SUBCODE}; these are outside it: {found:#?}"
    );
}

#[test]
fn a_subcode_above_the_range_is_reported() {
    let one_past = violations("crates/iec61850-server/src/service/mod.rs", &sample("5"));
    assert_eq!(
        one_past.len(),
        1,
        "subcode 5 is one past object-invalidated and must be reported"
    );

    let data_access_error_code =
        violations("crates/iec61850-server/src/service/mod.rs", &sample("10"));
    assert_eq!(
        data_access_error_code.len(),
        1,
        "10 is the DataAccessError code for object-non-existent, not an access subcode"
    );
}

#[test]
fn literals_and_named_subcodes_within_the_range_are_accepted() {
    for src in [
        "ErrorClass::Access(0)",
        "ErrorClass::Access(4)",
        "ErrorClass::Access(access::OBJECT_NON_EXISTENT)",
        "ErrorClass::Access(subcode::access::OBJECT_ACCESS_UNSUPPORTED)",
    ] {
        assert!(
            violations("crates/iec61850-server/src/service/mod.rs", src).is_empty(),
            "{src} is within the range"
        );
    }
}

#[test]
fn a_binding_is_allowed_only_where_the_enum_is_defined() {
    let definition = "crates/iec61850-mms/src/mms/pdu/service_error.rs";
    for src in [
        "ErrorClass::Access(_) => 7,",
        "ErrorClass::Access(c) => *c,",
        "7 => ErrorClass::Access(code),",
    ] {
        assert!(
            violations(definition, src).is_empty(),
            "{src} destructures where the enum is defined"
        );
        assert_eq!(
            violations("crates/iec61850-server/src/service/mod.rs", src).len(),
            1,
            "{src} must be reported outside the file that defines the enum"
        );
    }
}

#[test]
fn an_argument_the_scan_cannot_check_is_reported() {
    let found = violations(
        "crates/iec61850-server/src/service/mod.rs",
        "ErrorClass::Access(DataAccessError::ObjectNonExistent as u8)",
    );
    assert_eq!(
        found.len(),
        1,
        "an argument whose value the scan cannot read must not pass"
    );
}

#[test]
fn every_occurrence_in_a_file_is_found() {
    let src = "\
        let a = ErrorClass::Access(0);\n\
        let b = ErrorClass::Access(access::OBJECT_NON_EXISTENT);\n\
        let c = ErrorClass::Definition(definition::OBJECT_EXISTS);\n";
    let args = arguments(src);
    assert_eq!(args.len(), 2, "only the access alternative is scanned");
    assert_eq!(args[0], "0");
    assert_eq!(args[1], "access::OBJECT_NON_EXISTENT");
}
