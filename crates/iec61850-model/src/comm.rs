//! Communication addressing: the address parameters an SCL `<Communication>`
//! section gives an access point, a GOOSE control block and a sampled values
//! control block (IEC 61850-6 §9.4).
//!
//! An [`Address`] holds the `<P>` parameters of one SCL `<Address>` in document
//! order, each value as written. The schema form of a predefined type of
//! `tPTypeEnum` is the pattern of its `tP_` restriction in the SCL schema,
//! together with the character limits of IEC 61850-8-1 §25.3.1 Table 162 and
//! §25.3 Tables 163 and 164; [`check_parameter`] tells whether a value has it.
//! A value written another way that still reads without ambiguity, such as a
//! lower-case MAC address or a VLAN-ID of one digit, is kept and read by the
//! typed accessors ([`value_form`] tells it apart); a value that cannot be read
//! is kept too, and its accessor returns `None`, so the code that uses it
//! decides how to fail.
//!
//! These types only describe addressing. Nothing in this crate opens a socket
//! or binds an address; the GOOSE and sampled values crates turn an address
//! into their publisher settings, and binding the server address stays with
//! the application.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::compat::prelude::*;
use thiserror::Error;

/// Why an address parameter was refused.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    /// The `type` is neither a predefined address type nor a well-formed
    /// extension type, which starts with an upper-case letter followed by
    /// letters, digits and hyphens.
    #[error("`{p_type}` is not an address parameter type")]
    #[non_exhaustive]
    InvalidType {
        /// The type as written.
        p_type: String,
    },

    /// The value does not have the form the type prescribes.
    #[error("address parameter `{p_type}` expects {expected}, saw `{value}`")]
    #[non_exhaustive]
    InvalidValue {
        /// The parameter type.
        p_type: String,
        /// The value as written.
        value: String,
        /// The form the type prescribes, for the message.
        expected: &'static str,
    },
}

/// One `<P>` of an SCL `<Address>`: its type and its value as written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AddressParameter {
    /// The `type` attribute, for example `MAC-Address`.
    pub p_type: String,
    /// The element text.
    pub value: String,
}

/// The address parameters of an SCL `<Address>`, in document order.
///
/// Built with [`push`](Self::push) or [`with`](Self::with), which keep each
/// value as written. The typed accessors read a value in the schema form and
/// one written another way that reads without ambiguity, white space around
/// it included, and return `None` for a parameter that is absent or cannot be
/// read. When a type occurs more than
/// once, the accessors read the first occurrence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Address {
    parameters: Vec<AddressParameter>,
}

impl Address {
    /// Creates an address with no parameter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the parameter `p_type` with the value `value`.
    ///
    /// The value is kept as written, whether or not it has the schema form of
    /// its type; see [`value_form`].
    ///
    /// # Errors
    ///
    /// [`AddressError::InvalidType`] when `p_type` is not an address parameter
    /// type, and [`AddressError::InvalidValue`] when `value` holds nothing but
    /// white space (`tPAddr` is a non-empty string); the address is then left
    /// unchanged.
    pub fn push(
        &mut self,
        p_type: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), AddressError> {
        let p_type = p_type.into();
        let value = value.into();
        check_type_and_text(&p_type, &value)?;
        self.parameters.push(AddressParameter { p_type, value });
        Ok(())
    }

    /// Returns the address with the parameter `p_type` added, as
    /// [`push`](Self::push) adds it.
    ///
    /// # Errors
    ///
    /// As [`push`](Self::push).
    pub fn with(
        mut self,
        p_type: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, AddressError> {
        self.push(p_type, value)?;
        Ok(self)
    }

    /// Returns the parameters in the order they were added.
    pub fn parameters(&self) -> &[AddressParameter] {
        &self.parameters
    }

    /// Returns whether the address holds no parameter.
    pub fn is_empty(&self) -> bool {
        self.parameters.is_empty()
    }

    /// Returns the value of the first parameter of type `p_type`, as written.
    pub fn get(&self, p_type: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|p| p.p_type == p_type)
            .map(|p| p.value.as_str())
    }

    /// Returns the value of the first parameter of type `p_type` without the
    /// white space around it, as the typed accessors read it.
    fn text(&self, p_type: &str) -> Option<&str> {
        self.get(p_type).map(trim_xml_space)
    }

    /// Returns the `MAC-Address`: six octets of one or two hexadecimal digits
    /// of either case, separated by `-` or `:`.
    pub fn mac_address(&self) -> Option<[u8; 6]> {
        read_mac(self.text("MAC-Address")?)
    }

    /// Returns the `APPID`: one to four hexadecimal digits of either case.
    pub fn app_id(&self) -> Option<u16> {
        read_hex(self.text("APPID")?, 4)
    }

    /// Returns the `VLAN-ID`: one to three hexadecimal digits of either case.
    pub fn vlan_id(&self) -> Option<u16> {
        read_hex(self.text("VLAN-ID")?, 3)
    }

    /// Returns the `VLAN-PRIORITY`: a decimal number from 0 to 7.
    pub fn vlan_priority(&self) -> Option<u8> {
        read_decimal(self.text("VLAN-PRIORITY")?, 7).map(|p| p as u8)
    }

    /// Returns the IPv4 address `IP`.
    pub fn ip(&self) -> Option<Ipv4Addr> {
        read_ipv4(self.text("IP")?)
    }

    /// Returns the IPv4 network mask `IP-SUBNET`.
    pub fn ip_subnet(&self) -> Option<Ipv4Addr> {
        read_ipv4(self.text("IP-SUBNET")?)
    }

    /// Returns the first-hop IPv4 gateway `IP-GATEWAY`; `0.0.0.0` means none is
    /// configured (IEC 61850-8-1 §25.3.1 Table 162).
    pub fn ip_gateway(&self) -> Option<Ipv4Addr> {
        read_ipv4(self.text("IP-GATEWAY")?)
    }

    /// Returns the IPv6 address `IPv6`, in any notation of RFC 4291 §2.2.
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.text("IPv6")?.parse().ok()
    }

    /// Returns the TCP port of the MMS server, `MMS-Port`.
    pub fn mms_port(&self) -> Option<u16> {
        read_decimal(self.text("MMS-Port")?, 65_535).map(|p| p as u16)
    }

    /// Returns the OSI presentation selector `OSI-PSEL` as octets.
    pub fn osi_psel(&self) -> Option<Vec<u8>> {
        read_octets(self.text("OSI-PSEL")?, 8)
    }

    /// Returns the OSI session selector `OSI-SSEL` as octets.
    pub fn osi_ssel(&self) -> Option<Vec<u8>> {
        read_octets(self.text("OSI-SSEL")?, 8)
    }

    /// Returns the OSI transport selector `OSI-TSEL` as octets.
    pub fn osi_tsel(&self) -> Option<Vec<u8>> {
        read_octets(self.text("OSI-TSEL")?, 4)
    }

    /// Returns the arcs of the ACSE AP title `OSI-AP-Title`, an object
    /// identifier written as numbers separated by commas or white space.
    pub fn osi_ap_title(&self) -> Option<Vec<u32>> {
        read_arcs(self.text("OSI-AP-Title")?)
    }

    /// Returns the ACSE AE qualifier `OSI-AE-Qualifier`.
    pub fn osi_ae_qualifier(&self) -> Option<u32> {
        read_decimal(self.text("OSI-AE-Qualifier")?, u32::MAX)
    }
}

/// How a parameter value relates to the schema form of its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueForm {
    /// The value has the schema form, or its type is an extension type.
    Canonical,
    /// The value is written another way that reads without ambiguity, such as
    /// a lower-case MAC address, a VLAN-ID of fewer than three digits, OSI
    /// selector octets separated by white space, or a value with white space
    /// around it; the typed accessors read it, and [`schema_value`] writes it
    /// in the schema form.
    Readable,
    /// The value cannot be read as its type, such as a MAC address of five
    /// octets or a VLAN-ID above 0xFFF; the typed accessor returns `None`.
    Unreadable,
}

/// Tells whether the value of a parameter has the schema form of its type,
/// reads another way, or cannot be read; see [`ValueForm`].
///
/// A type that is not an address parameter type, and a value of nothing but
/// white space, are [`ValueForm::Unreadable`]. White space around a value, a
/// line break or a tab included, is read past, as the `normalizedString` of
/// `tPAddr` and the `collapse` of a number type allow.
pub fn value_form(p_type: &str, value: &str) -> ValueForm {
    if check_parameter(p_type, value).is_ok() {
        ValueForm::Canonical
    } else if schema_value(p_type, value).is_some() {
        ValueForm::Readable
    } else {
        ValueForm::Unreadable
    }
}

/// Returns the value of a parameter as read, written in the schema form of
/// its type, or `None` when it cannot be read: `"1"` as a `VLAN-ID` is `"001"`,
/// `"10"` as an `APPID` is `"0010"`, since a short value is hexadecimal as the
/// schema form is, and `"1"` as an OSI selector is the octet `"01"`, an odd run
/// of digits taking one leading zero. An extension type, which prescribes no
/// form, returns the value without the white space around it.
pub fn schema_value(p_type: &str, value: &str) -> Option<String> {
    check_type_and_text(p_type, value).ok()?;
    let text = trim_xml_space(value);
    let hex_octets_text = |octets: Vec<u8>| {
        octets
            .iter()
            .map(|o| format!("{o:02X}"))
            .collect::<Vec<_>>()
            .concat()
    };
    match p_type {
        "IP" | "IP-SUBNET" | "IP-GATEWAY" | "IP-IGMPv3Src" => {
            read_ipv4(text).map(|ip| ip.to_string())
        }
        "IPv6" | "IPv6-GATEWAY" | "IPv6-IGMPv3Src" => text.parse::<Ipv6Addr>().ok().map(|ip| {
            ip.segments()
                .iter()
                .map(|s| format!("{s:x}"))
                .collect::<Vec<_>>()
                .join(":")
        }),
        "IPv6-SUBNET" => read_decimal(text.strip_prefix('/').unwrap_or(text), 127)
            .filter(|n| *n >= 1)
            .map(|n| format!("/{n}")),
        "DNSName" => (!text.contains(char::is_whitespace)).then(|| text.to_string()),
        "IPv6FlowLabel" => read_hex(text, 5).map(|v| format!("{v:X}")),
        "OSI-NSAP" => read_octets(text, 20).map(hex_octets_text),
        "OSI-TSEL" => read_octets(text, 4).map(hex_octets_text),
        "OSI-SSEL" | "OSI-PSEL" => read_octets(text, 8).map(hex_octets_text),
        "OSI-AP-Title" => read_arcs(text).map(|arcs| {
            arcs.iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",")
        }),
        "OSI-AP-Invoke" | "OSI-AE-Qualifier" | "OSI-AE-Invoke" => {
            read_decimal(text, u32::MAX).map(|n| n.to_string())
        }
        "MAC-Address" => read_mac(text).map(|mac| {
            mac.iter()
                .map(|o| format!("{o:02X}"))
                .collect::<Vec<_>>()
                .join("-")
        }),
        "APPID" => read_hex(text, 4).map(|v| format!("{v:04X}")),
        "VLAN-PRIORITY" => read_decimal(text, 7).map(|n| n.to_string()),
        "VLAN-ID" => read_hex(text, 3).map(|v| format!("{v:03X}")),
        "SNTP-Port" | "MMS-Port" | "IP-UDP-PORT" | "IP-TCP-PORT" => {
            read_decimal(text, 65_535).map(|n| n.to_string())
        }
        "IPv6ClassOfTraffic" => read_decimal(text, 255).map(|n| n.to_string()),
        "C37-118-IP-Port" => read_decimal(text, 65_535)
            .filter(|n| *n >= 1025)
            .map(|n| n.to_string()),
        "IP-ClassOfTraffic" => read_hex(text, 2).map(|v| format!("{v:02X}")),
        _ => Some(text.to_string()),
    }
}

/// Returns `text` without the XML white space, spaces, tabs, carriage returns
/// and line feeds, around it.
fn trim_xml_space(text: &str) -> &str {
    text.trim_matches([' ', '\t', '\r', '\n'])
}

/// The schema form of a predefined type, as words for a message.
pub fn schema_form(p_type: &str) -> &'static str {
    expected_form(p_type)
}

/// Checks that `p_type` is an address parameter type and that `value` holds
/// more than white space, as a `tPAddr` must.
fn check_type_and_text(p_type: &str, value: &str) -> Result<(), AddressError> {
    if !is_predefined_type(p_type) && !is_extension_type(p_type) {
        return Err(AddressError::InvalidType {
            p_type: p_type.to_string(),
        });
    }
    if trim_xml_space(value).is_empty() {
        return Err(AddressError::InvalidValue {
            p_type: p_type.to_string(),
            value: value.to_string(),
            expected: "a non-empty string",
        });
    }
    Ok(())
}

fn is_predefined_type(p_type: &str) -> bool {
    matches!(
        p_type,
        "IP" | "IP-SUBNET"
            | "IP-GATEWAY"
            | "OSI-NSAP"
            | "OSI-TSEL"
            | "OSI-SSEL"
            | "OSI-PSEL"
            | "OSI-AP-Title"
            | "OSI-AP-Invoke"
            | "OSI-AE-Qualifier"
            | "OSI-AE-Invoke"
            | "MAC-Address"
            | "APPID"
            | "VLAN-PRIORITY"
            | "VLAN-ID"
            | "SNTP-Port"
            | "MMS-Port"
            | "DNSName"
            | "IPv6FlowLabel"
            | "IPv6ClassOfTraffic"
            | "C37-118-IP-Port"
            | "IP-UDP-PORT"
            | "IP-TCP-PORT"
            | "IPv6"
            | "IPv6-SUBNET"
            | "IPv6-GATEWAY"
            | "IPv6-IGMPv3Src"
            | "IP-IGMPv3Src"
            | "IP-ClassOfTraffic"
    )
}

/// Reads one to `max_digits` hexadecimal digits of either case.
fn read_hex(text: &str, max_digits: usize) -> Option<u16> {
    if text.is_empty() || text.len() > max_digits || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(text, 16)
        .ok()
        .and_then(|v| u16::try_from(v).ok())
}

/// Reads a decimal number, leading zeros allowed, of at most `max`.
fn read_decimal(text: &str, max: u32) -> Option<u32> {
    if !is_decimal(text) {
        return None;
    }
    let digits = text.trim_start_matches('0');
    if digits.len() > 10 {
        return None;
    }
    let value: u64 = if digits.is_empty() {
        0
    } else {
        digits.parse().ok()?
    };
    u32::try_from(value).ok().filter(|v| *v <= max)
}

/// Reads a MAC address: six octets of one or two hexadecimal digits of either
/// case, all separated by `-` or all by `:`.
fn read_mac(text: &str) -> Option<[u8; 6]> {
    let separator = if text.contains('-') { '-' } else { ':' };
    let mut mac = [0u8; 6];
    let mut parts = text.split(separator);
    for octet in &mut mac {
        let part = parts.next()?;
        if !(1..=2).contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *octet = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// Reads a dotted-decimal IPv4 address: four decimal octets, leading zeros
/// allowed.
fn read_ipv4(text: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.len() > 3 {
            return None;
        }
        *octet = u8::try_from(read_decimal(part, 255)?).ok()?;
    }
    parts.next().is_none().then(|| Ipv4Addr::from(octets))
}

/// Reads octets written as hexadecimal digits of either case: groups of one
/// or two digits separated by white space, or one run of digits, an odd run
/// read with a leading zero. At least one and at most `max_octets` octets.
fn read_octets(text: &str, max_octets: usize) -> Option<Vec<u8>> {
    let octets: Option<Vec<u8>> = if text.contains(char::is_whitespace) {
        text.split_whitespace()
            .map(|group| {
                ((1..=2).contains(&group.len()) && group.bytes().all(|b| b.is_ascii_hexdigit()))
                    .then(|| u8::from_str_radix(group, 16).ok())
                    .flatten()
            })
            .collect()
    } else {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let padded = if text.len() % 2 == 1 {
            format!("0{text}")
        } else {
            text.to_string()
        };
        hex_octets(&padded)
    };
    octets.filter(|o| (1..=max_octets).contains(&o.len()))
}

/// Reads the arcs of an object identifier written as decimal numbers
/// separated by commas, white space, or both.
fn read_arcs(text: &str) -> Option<Vec<u32>> {
    let arcs: Option<Vec<u32>> = text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|arc| !arc.is_empty())
        .map(|arc| read_decimal(arc, u32::MAX))
        .collect();
    arcs.filter(|a| !a.is_empty())
}

/// The addressing of a GOOSE control block: an SCL `<GSE>` (IEC 61850-6
/// §9.4.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GseAddress {
    /// The `<Address>`; empty when the element has none.
    pub address: Address,
    /// The `<MinTime>`, in milliseconds: the delay between the first
    /// transmission of a change and its first repetition.
    pub min_time_ms: Option<u32>,
    /// The `<MaxTime>`, in milliseconds: the source supervision time, the
    /// longest interval between two repetitions.
    pub max_time_ms: Option<u32>,
}

impl GseAddress {
    /// Creates the addressing `address`, with no `MinTime` and no `MaxTime`.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            min_time_ms: None,
            max_time_ms: None,
        }
    }
}

/// An access point of the IED connected to a subnetwork: an SCL
/// `<ConnectedAP>` with the subnetwork it belongs to (IEC 61850-6 §9.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectedAccessPoint {
    /// The `name` of the `<SubNetwork>`.
    pub sub_network: String,
    /// The `type` of the `<SubNetwork>`, the protocol it carries, for example
    /// `8-MMS`.
    pub sub_network_type: Option<String>,
    /// The `apName`, naming the access point of the IED.
    pub ap_name: String,
    /// The server address of the access point, from its `<Address>`.
    pub address: Option<Address>,
}

impl ConnectedAccessPoint {
    /// Creates the connection of the access point `ap_name` to the subnetwork
    /// `sub_network`, with no subnetwork type and no address.
    pub fn new(sub_network: impl Into<String>, ap_name: impl Into<String>) -> Self {
        Self {
            sub_network: sub_network.into(),
            sub_network_type: None,
            ap_name: ap_name.into(),
            address: None,
        }
    }
}

/// Checks that an address parameter has the schema form: `p_type` must be a
/// predefined type of `tPTypeEnum` or a well-formed extension type, and
/// `value` must have the form the type prescribes.
///
/// The schema form is the canonical one. An address keeps a value that breaks
/// it, and the accessors still read one that reads without ambiguity
/// ([`value_form`]); a loader reports such a value as a warning, with the form
/// this function expects.
///
/// Every value is a non-empty string free of carriage returns, line feeds and
/// tabs (`tPAddr`). A predefined type further restricts it to the pattern of its
/// `tP_` type in the SCL schema of IEC 61850-6 Annex A; the OSI selectors and
/// the NSAP must also hold an even number of characters (IEC 61850-8-1 §25.3.1
/// Table 162). An extension type accepts any such string.
///
/// Where the schema is narrower than the character rules of IEC 61850-8-1
/// Table 162, the schema applies: an IPv6 address takes lower-case digits only,
/// although the RFC 4291 notation the table cites is case-insensitive, and a
/// port takes no leading zero, although the table only limits it to five
/// digits.
///
/// # Errors
///
/// [`AddressError::InvalidType`] or [`AddressError::InvalidValue`].
pub fn check_parameter(p_type: &str, value: &str) -> Result<(), AddressError> {
    let invalid = |expected: &'static str| AddressError::InvalidValue {
        p_type: p_type.to_string(),
        value: value.to_string(),
        expected,
    };
    if value.is_empty() || value.contains(['\r', '\n', '\t']) {
        return Err(invalid("a non-empty string without line breaks or tabs"));
    }
    let ok = match p_type {
        "IP" | "IP-SUBNET" | "IP-GATEWAY" | "IP-IGMPv3Src" => {
            return schema_ipv4(value)
                .map(|_| ())
                .ok_or_else(|| invalid("a dotted-decimal IPv4 address"))
        }
        "IPv6" | "IPv6-GATEWAY" | "IPv6-IGMPv3Src" => is_full_ipv6(value),
        "IPv6-SUBNET" => value
            .strip_prefix('/')
            .filter(|n| is_decimal(n) && !n.starts_with('0'))
            .and_then(|n| n.parse::<u8>().ok())
            .is_some_and(|n| (1..=127).contains(&n)),
        "DNSName" => !value.contains(char::is_whitespace),
        "IPv6FlowLabel" => {
            (1..=5).contains(&value.len()) && value.chars().all(|c| c.is_ascii_hexdigit())
        }
        "OSI-NSAP" => is_even_upper_hex(value, 40),
        "OSI-TSEL" => is_even_upper_hex(value, 8),
        "OSI-SSEL" | "OSI-PSEL" => is_even_upper_hex(value, 16),
        "OSI-AP-Title" => value.chars().all(|c| c.is_ascii_digit() || c == ','),
        "OSI-AP-Invoke" | "OSI-AE-Qualifier" | "OSI-AE-Invoke" => {
            value.len() <= 5 && is_decimal(value)
        }
        "MAC-Address" => {
            value.len() == 17
                && value.split('-').count() == 6
                && value
                    .split('-')
                    .all(|pair| pair.len() == 2 && is_upper_hex(pair))
        }
        "APPID" => value.len() == 4 && is_upper_hex(value),
        "VLAN-PRIORITY" => matches!(value.as_bytes(), [b'0'..=b'7']),
        "VLAN-ID" => value.len() == 3 && is_upper_hex(value),
        "SNTP-Port" | "MMS-Port" | "IP-UDP-PORT" | "IP-TCP-PORT" => {
            canonical_decimal(value).is_some_and(|n| n <= 65_535)
        }
        "IPv6ClassOfTraffic" => canonical_decimal(value).is_some_and(|n| n <= 255),
        "C37-118-IP-Port" => canonical_decimal(value).is_some_and(|n| (1025..=65_535).contains(&n)),
        "IP-ClassOfTraffic" => value.len() <= 2 && is_upper_hex(value),
        other => {
            if !is_extension_type(other) {
                return Err(AddressError::InvalidType {
                    p_type: p_type.to_string(),
                });
            }
            true
        }
    };
    if ok {
        Ok(())
    } else {
        Err(invalid(expected_form(p_type)))
    }
}

/// The form a predefined type prescribes, for the error message.
fn expected_form(p_type: &str) -> &'static str {
    match p_type {
        "IPv6" | "IPv6-GATEWAY" | "IPv6-IGMPv3Src" => {
            "eight groups of one to four lower-case hexadecimal digits separated by `:`"
        }
        "IPv6-SUBNET" => "`/` followed by a prefix length from 1 to 127",
        "DNSName" => "a name without white space",
        "IPv6FlowLabel" => "one to five hexadecimal digits",
        "OSI-NSAP" => "an even number, at most 40, of digits 0-9 and A-F",
        "OSI-TSEL" => "an even number, at most 8, of digits 0-9 and A-F",
        "OSI-SSEL" | "OSI-PSEL" => "an even number, at most 16, of digits 0-9 and A-F",
        "OSI-AP-Title" => "digits and commas",
        "OSI-AP-Invoke" | "OSI-AE-Qualifier" | "OSI-AE-Invoke" => "one to five decimal digits",
        "MAC-Address" => "six pairs of digits 0-9 and A-F separated by `-`",
        "APPID" => "four digits 0-9 and A-F",
        "VLAN-PRIORITY" => "a single digit 0-7",
        "VLAN-ID" => "three digits 0-9 and A-F",
        "SNTP-Port" | "MMS-Port" | "IP-UDP-PORT" | "IP-TCP-PORT" => {
            "a decimal port number from 0 to 65535"
        }
        "IPv6ClassOfTraffic" => "a decimal number from 0 to 255",
        "C37-118-IP-Port" => "a decimal port number from 1025 to 65535",
        "IP-ClassOfTraffic" => "one or two digits 0-9 and A-F",
        _ => "a value of the form its type prescribes",
    }
}

/// Returns whether `name` is an extension type of `tExtensionPTypeEnum`: an
/// upper-case letter followed by letters, digits and hyphens.
fn is_extension_type(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn is_upper_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fn is_even_upper_hex(text: &str, max_len: usize) -> bool {
    text.len() <= max_len && text.len().is_multiple_of(2) && is_upper_hex(text)
}

/// Parses a decimal number written without leading zeros.
fn canonical_decimal(text: &str) -> Option<u32> {
    if !is_decimal(text) || (text.len() > 1 && text.starts_with('0')) || text.len() > 5 {
        return None;
    }
    text.parse().ok()
}

/// Parses a dotted-decimal IPv4 address in the form of the `tP_IPbase` pattern:
/// four decimal octets, each at most three digits, a three-digit one without a
/// leading zero.
fn schema_ipv4(text: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if !is_decimal(part) || part.len() > 3 || (part.len() == 3 && part.starts_with('0')) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    parts.next().is_none().then(|| Ipv4Addr::from(octets))
}

/// Returns whether `text` is eight groups of one to four lower-case
/// hexadecimal digits separated by colons, the `tP_IPv6base` pattern.
fn is_full_ipv6(text: &str) -> bool {
    let groups: Vec<&str> = text.split(':').collect();
    groups.len() == 8
        && groups.iter().all(|g| {
            (1..=4).contains(&g.len())
                && g.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Decodes a string of hexadecimal digit pairs.
fn hex_octets(text: &str) -> Option<Vec<u8>> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            core::str::from_utf8(pair)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejects(p_type: &str, value: &str) -> bool {
        matches!(
            check_parameter(p_type, value),
            Err(AddressError::InvalidValue { .. })
        )
    }

    #[test]
    fn ipv4_types_take_dotted_decimal() {
        for t in ["IP", "IP-SUBNET", "IP-GATEWAY", "IP-IGMPv3Src"] {
            assert_eq!(check_parameter(t, "10.0.0.11"), Ok(()));
            assert_eq!(check_parameter(t, "255.255.255.0"), Ok(()));
            assert_eq!(check_parameter(t, "01.2.3.4"), Ok(()));
            for bad in [
                "10.0.0",
                "10.0.0.256",
                "10.0.0.1.1",
                "a.b.c.d",
                "010.0.0.1",
                "10..0.1",
            ] {
                assert!(rejects(t, bad), "{t} {bad}");
            }
        }
    }

    #[test]
    fn ipv6_types_take_eight_lower_case_groups() {
        assert_eq!(check_parameter("IPv6", "fe80:0:0:0:0:0:0:1"), Ok(()));
        assert!(rejects("IPv6", "fe80::1"));
        assert!(rejects("IPv6", "FE80:0:0:0:0:0:0:1"));
        assert_eq!(check_parameter("IPv6-SUBNET", "/64"), Ok(()));
        for bad in ["/0", "/128", "64", "/064"] {
            assert!(rejects("IPv6-SUBNET", bad), "{bad}");
        }
    }

    #[test]
    fn layer_two_types_follow_the_schema_patterns() {
        assert_eq!(check_parameter("MAC-Address", "01-0C-CD-01-00-01"), Ok(()));
        for bad in [
            "01-0c-cd-01-00-01",
            "01:0C:CD:01:00:01",
            "01-0C-CD-01-00",
            "01-0C-CD-01-00-01-02",
            "1-0C-CD-01-00-001",
        ] {
            assert!(rejects("MAC-Address", bad), "{bad}");
        }
        assert_eq!(check_parameter("APPID", "3A00"), Ok(()));
        for bad in ["3a00", "300", "30000", "G000"] {
            assert!(rejects("APPID", bad), "{bad}");
        }
        assert_eq!(check_parameter("VLAN-ID", "0FF"), Ok(()));
        for bad in ["FF", "0fff", "0ff", "0"] {
            assert!(rejects("VLAN-ID", bad), "{bad}");
        }
        for p in 0..=7 {
            assert_eq!(check_parameter("VLAN-PRIORITY", &p.to_string()), Ok(()));
        }
        for bad in ["8", "04", "-1", "a"] {
            assert!(rejects("VLAN-PRIORITY", bad), "{bad}");
        }
    }

    #[test]
    fn osi_types_follow_the_schema_and_table_162() {
        assert_eq!(check_parameter("OSI-TSEL", "00000001"), Ok(()));
        assert!(rejects("OSI-TSEL", "000000001"));
        assert!(rejects("OSI-TSEL", "001"));
        assert!(rejects("OSI-PSEL", "0a"));
        assert_eq!(check_parameter("OSI-SSEL", "0001"), Ok(()));
        assert_eq!(check_parameter("OSI-AP-Title", "1,1,9999,1"), Ok(()));
        assert!(rejects("OSI-AP-Title", "1.1.9999.1"));
        assert_eq!(check_parameter("OSI-AE-Qualifier", "12"), Ok(()));
        assert!(rejects("OSI-AE-Qualifier", "123456"));
        assert_eq!(check_parameter("OSI-NSAP", &"AB".repeat(20)), Ok(()));
        assert!(rejects("OSI-NSAP", &"AB".repeat(21)));
    }

    #[test]
    fn port_types_take_canonical_decimals() {
        for t in ["MMS-Port", "SNTP-Port", "IP-UDP-PORT", "IP-TCP-PORT"] {
            assert_eq!(check_parameter(t, "0"), Ok(()));
            assert_eq!(check_parameter(t, "102"), Ok(()));
            assert_eq!(check_parameter(t, "65535"), Ok(()));
            for bad in ["65536", "0102", "-1", "1e3"] {
                assert!(rejects(t, bad), "{t} {bad}");
            }
        }
        assert!(rejects("C37-118-IP-Port", "1024"));
        assert_eq!(check_parameter("C37-118-IP-Port", "4712"), Ok(()));
        assert!(rejects("IPv6ClassOfTraffic", "256"));
        assert_eq!(check_parameter("IP-ClassOfTraffic", "B8"), Ok(()));
        assert!(rejects("IP-ClassOfTraffic", "B80"));
    }

    #[test]
    fn extension_types_take_any_value_and_need_a_well_formed_name() {
        assert_eq!(check_parameter("Vendor-Thing2", "any text"), Ok(()));
        assert_eq!(
            check_parameter("vendor", "x"),
            Err(AddressError::InvalidType {
                p_type: "vendor".into()
            })
        );
        assert!(matches!(
            check_parameter("Bad_Name", "x"),
            Err(AddressError::InvalidType { .. })
        ));
    }

    #[test]
    fn every_value_is_non_empty_and_single_line() {
        assert!(rejects("Vendor", ""));
        assert!(rejects("Vendor", "a\tb"));
        assert!(rejects("IP", ""));
    }

    #[test]
    fn accessors_decode_the_parameters() {
        let address = Address::new()
            .with("IP", "10.0.0.11")
            .and_then(|a| a.with("IP-SUBNET", "255.255.255.0"))
            .and_then(|a| a.with("IP-GATEWAY", "10.0.0.101"))
            .and_then(|a| a.with("MMS-Port", "102"))
            .and_then(|a| a.with("OSI-TSEL", "00000001"))
            .and_then(|a| a.with("OSI-PSEL", "01"))
            .and_then(|a| a.with("OSI-SSEL", "0001"))
            .and_then(|a| a.with("OSI-AP-Title", "1,1,9999,1"))
            .and_then(|a| a.with("OSI-AE-Qualifier", "12"))
            .and_then(|a| a.with("MAC-Address", "01-0C-CD-04-00-01"))
            .and_then(|a| a.with("APPID", "4000"))
            .and_then(|a| a.with("VLAN-ID", "07B"))
            .and_then(|a| a.with("VLAN-PRIORITY", "6"))
            .and_then(|a| a.with("IPv6", "fe80:0:0:0:0:0:0:1"))
            .expect("valid address");
        assert_eq!(address.ip(), Some(Ipv4Addr::new(10, 0, 0, 11)));
        assert_eq!(address.ip_subnet(), Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(address.ip_gateway(), Some(Ipv4Addr::new(10, 0, 0, 101)));
        assert_eq!(address.mms_port(), Some(102));
        assert_eq!(address.osi_tsel(), Some(vec![0, 0, 0, 1]));
        assert_eq!(address.osi_psel(), Some(vec![1]));
        assert_eq!(address.osi_ssel(), Some(vec![0, 1]));
        assert_eq!(address.osi_ap_title(), Some(vec![1, 1, 9999, 1]));
        assert_eq!(address.osi_ae_qualifier(), Some(12));
        assert_eq!(
            address.mac_address(),
            Some([0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01])
        );
        assert_eq!(address.app_id(), Some(0x4000));
        assert_eq!(address.vlan_id(), Some(0x07b));
        assert_eq!(address.vlan_priority(), Some(6));
        assert_eq!(
            address.ipv6(),
            Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(address.get("Absent"), None);
        assert_eq!(Address::new().mac_address(), None);
    }

    #[test]
    fn a_refused_parameter_leaves_the_address_unchanged() {
        let mut address = Address::new();
        assert!(address.push("APPID", "").is_err());
        assert!(address.push("APPID", "  ").is_err());
        assert!(address.push("appid", "0001").is_err());
        assert!(address.is_empty());
        address.push("APPID", "0001").expect("valid");
        address.push("APPID", "0002").expect("valid");
        assert_eq!(address.app_id(), Some(1), "the first occurrence is read");
    }

    #[test]
    fn values_written_another_way_read_and_are_kept() {
        let cases: &[(&str, &str)] = &[
            ("MAC-Address", "01-0c-cd-01-00-01"),
            ("MAC-Address", "01:0C:CD:01:00:01"),
            ("MAC-Address", "1-c-cd-1-0-1"),
            ("APPID", "1"),
            ("APPID", "3a01"),
            ("VLAN-ID", "1"),
            ("VLAN-ID", "7b"),
            ("VLAN-PRIORITY", "04"),
            ("IP", "010.000.000.001"),
            ("IPv6", "FE80::1"),
            ("IPv6-SUBNET", "64"),
            ("OSI-TSEL", "00 00 00 01"),
            ("OSI-SSEL", "1"),
            ("OSI-PSEL", "0 0 0 1"),
            ("OSI-AP-Title", "1 3 9999 33"),
            ("OSI-AP-Title", "1, 3, 9999, 33"),
            ("OSI-AE-Qualifier", "123456"),
            ("MMS-Port", "0102"),
        ];
        for (t, v) in cases {
            assert_eq!(value_form(t, v), ValueForm::Readable, "{t} `{v}`");
        }
        let a = Address::new()
            .with("MAC-Address", "01:0c:cd:01:00:01")
            .and_then(|a| a.with("APPID", "1"))
            .and_then(|a| a.with("VLAN-ID", "1"))
            .and_then(|a| a.with("VLAN-PRIORITY", "04"))
            .and_then(|a| a.with("IP", "010.000.000.001"))
            .and_then(|a| a.with("IPv6", "FE80::1"))
            .and_then(|a| a.with("OSI-TSEL", "00 00 00 01"))
            .and_then(|a| a.with("OSI-SSEL", "1"))
            .and_then(|a| a.with("OSI-PSEL", "0 0 0 1"))
            .and_then(|a| a.with("OSI-AP-Title", "1 3 9999 33"))
            .and_then(|a| a.with("MMS-Port", "0102"))
            .expect("kept as written");
        assert_eq!(a.mac_address(), Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]));
        assert_eq!(a.app_id(), Some(1));
        assert_eq!(a.vlan_id(), Some(1));
        assert_eq!(a.vlan_priority(), Some(4));
        assert_eq!(a.ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(a.ipv6(), Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(a.osi_tsel(), Some(vec![0, 0, 0, 1]));
        assert_eq!(a.osi_ssel(), Some(vec![1]));
        assert_eq!(a.osi_psel(), Some(vec![0, 0, 0, 1]));
        assert_eq!(a.osi_ap_title(), Some(vec![1, 3, 9999, 33]));
        assert_eq!(a.mms_port(), Some(102));
        assert_eq!(a.get("VLAN-ID"), Some("1"), "kept as written");

        // A short value is hexadecimal, as the schema form is.
        let short = Address::new()
            .with("VLAN-ID", "10")
            .and_then(|a| a.with("APPID", "10"))
            .expect("kept as written");
        assert_eq!(short.vlan_id(), Some(0x010));
        assert_eq!(short.app_id(), Some(0x0010));
        assert_eq!(schema_value("VLAN-ID", "10").as_deref(), Some("010"));
        assert_eq!(schema_value("APPID", "10").as_deref(), Some("0010"));
        assert_eq!(schema_value("VLAN-ID", "1").as_deref(), Some("001"));
        assert_eq!(schema_value("OSI-SSEL", "1").as_deref(), Some("01"));
        assert_eq!(schema_value("OSI-TSEL", "001").as_deref(), Some("0001"));
        assert_eq!(
            schema_value("MAC-Address", "1:c:cd:1:0:5").as_deref(),
            Some("01-0C-CD-01-00-05")
        );
        assert_eq!(
            schema_value("OSI-AP-Title", "1 3 9999 33").as_deref(),
            Some("1,3,9999,33")
        );
        assert_eq!(
            schema_value("IPv6", "FE80::1").as_deref(),
            Some("fe80:0:0:0:0:0:0:1")
        );
        assert_eq!(schema_value("VLAN-ID", "1000"), None);
    }

    #[test]
    fn white_space_around_a_value_is_read_past() {
        for (t, v) in [
            ("MAC-Address", "01-0C-CD-01-00-01 "),
            ("APPID", "\n0001\n"),
            ("VLAN-ID", "\t07B\r\n"),
            ("OSI-TSEL", " 00 00\n00 01 "),
        ] {
            assert_eq!(value_form(t, v), ValueForm::Readable, "{t} {v:?}");
        }
        let a = Address::new()
            .with("MAC-Address", "01-0C-CD-01-00-01 ")
            .and_then(|a| a.with("APPID", "\n0001\n"))
            .and_then(|a| a.with("VLAN-ID", "\t07B\r\n"))
            .and_then(|a| a.with("OSI-TSEL", " 00 00\n00 01 "))
            .expect("kept as written");
        assert_eq!(a.mac_address(), Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]));
        assert_eq!(a.app_id(), Some(1));
        assert_eq!(a.vlan_id(), Some(0x07b));
        assert_eq!(a.osi_tsel(), Some(vec![0, 0, 0, 1]));
        assert_eq!(a.get("APPID"), Some("\n0001\n"), "kept as written");
        assert!(Address::new().push("APPID", " \n\t").is_err());
    }

    #[test]
    fn values_that_cannot_be_read_are_kept_and_read_as_none() {
        let cases: &[(&str, &str)] = &[
            ("MAC-Address", "01-0C-CD-01-00"),
            ("MAC-Address", "01-0C-CD-01-00-1G"),
            ("MAC-Address", "010-C-CD-01-00-01"),
            ("APPID", "10000"),
            ("VLAN-ID", "1000"),
            ("VLAN-ID", "g"),
            ("VLAN-PRIORITY", "8"),
            ("IP", "10.0.0.256"),
            ("OSI-TSEL", "00 00 00 00 01"),
            ("OSI-PSEL", "0x01"),
            ("OSI-AP-Title", "1.3.9999"),
            ("MMS-Port", "65536"),
            ("DNSName", "a b"),
        ];
        for (t, v) in cases {
            assert_eq!(value_form(t, v), ValueForm::Unreadable, "{t} `{v}`");
        }
        let a = Address::new()
            .with("MAC-Address", "01-0C-CD-01-00")
            .and_then(|a| a.with("VLAN-ID", "1000"))
            .and_then(|a| a.with("IP", "10.0.0.256"))
            .expect("kept as written");
        assert_eq!(a.mac_address(), None);
        assert_eq!(a.vlan_id(), None);
        assert_eq!(a.ip(), None);
        assert_eq!(a.get("MAC-Address"), Some("01-0C-CD-01-00"));
        assert_eq!(value_form("IP", "10.0.0.1"), ValueForm::Canonical);
        assert_eq!(value_form("Vendor-X", "anything"), ValueForm::Canonical);
        assert_eq!(value_form("ip", "10.0.0.1"), ValueForm::Unreadable);
    }
}
