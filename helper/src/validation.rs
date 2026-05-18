//! Pure input validation and canonicalization at the D-Bus trust
//! boundary. All public fns are called from [`crate::service`] and
//! reject untrusted input before it reaches `nft` or `ip` invocations.
//! No async, no I/O — fully unit-testable.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;

const IFNAMSIZ_MAX: usize = 15; // Linux IFNAMSIZ - 1 (NUL terminator)

/// Helper-enforced absolute ceiling on bypass CIDR list size.
/// The GUI-side GSettings limit (default 32, scheduled for Sprint 23 T3)
/// caps user-visible list length in the Preferences editor; this constant
/// is defence-in-depth at the trust boundary. Kept well below the kernel
/// `ip rule` O(n)-per-packet cost knee.
const MAX_BYPASS_CIDRS: usize = 128;

pub(crate) fn validate_interface(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("interface name empty");
    }
    if name.len() > IFNAMSIZ_MAX {
        bail!("interface name too long ({} > {IFNAMSIZ_MAX})", name.len());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        bail!("interface name contains invalid characters");
    }
    Ok(())
}

pub(crate) fn split_ips(ips: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        let parsed: IpAddr = ip.parse().with_context(|| format!("invalid IP '{ip}'"))?;
        match parsed {
            IpAddr::V4(_) => v4.push(ip.clone()),
            IpAddr::V6(_) => v6.push(ip.clone()),
        }
    }
    Ok((v4, v6))
}

/// Parse and validate a bypass CIDR list at the D-Bus trust boundary.
/// Returns canonicalized strings (host bits masked off) ready for storage.
///
/// Rejects: list size > [`MAX_BYPASS_CIDRS`], missing `/` prefix, invalid
/// address, prefix out of range, prefix `/0` (bypass everything is not a
/// meaningful rule), loopback, multicast, link-local (v4 169.254.0.0/16
/// and v6 fe80::/10), unspecified, and duplicates after canonicalization.
pub(crate) fn validate_bypass_cidrs(cidrs: &[String]) -> Result<Vec<String>> {
    if cidrs.len() > MAX_BYPASS_CIDRS {
        bail!(
            "bypass CIDR list too long: {} entries (max {})",
            cidrs.len(),
            MAX_BYPASS_CIDRS
        );
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(cidrs.len());
    for entry in cidrs {
        let canonical =
            canonicalize_cidr(entry).with_context(|| format!("invalid bypass CIDR '{entry}'"))?;
        if !seen.insert(canonical.clone()) {
            bail!(
                "duplicate bypass CIDR after canonicalization: '{}'",
                canonical
            );
        }
        out.push(canonical);
    }
    Ok(out)
}

fn canonicalize_cidr(s: &str) -> Result<String> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("missing '/' prefix length"))?;
    if addr_str.is_empty() || prefix_str.is_empty() {
        bail!("empty address or prefix");
    }
    let addr: IpAddr = addr_str
        .parse()
        .with_context(|| format!("invalid IP address '{addr_str}'"))?;
    let prefix: u8 = prefix_str
        .parse()
        .with_context(|| format!("invalid prefix length '{prefix_str}'"))?;

    if prefix == 0 {
        bail!("prefix /0 not allowed (would bypass entire internet)");
    }
    if addr.is_loopback() {
        bail!("loopback address not allowed in bypass list");
    }
    if addr.is_multicast() {
        bail!("multicast address not allowed in bypass list");
    }
    if addr.is_unspecified() {
        bail!("unspecified address (0.0.0.0 or ::) not allowed in bypass list");
    }

    match addr {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                bail!("IPv4 prefix /{prefix} exceeds /32");
            }
            let oct = v4.octets();
            if oct[0] == 169 && oct[1] == 254 {
                bail!("link-local IPv4 (169.254.0.0/16) not allowed in bypass list");
            }
            let bits = u32::from_be_bytes(oct);
            let mask: u32 = u32::MAX << (32 - prefix);
            let net = bits & mask;
            let net_addr = std::net::Ipv4Addr::from(net.to_be_bytes());
            Ok(format!("{net_addr}/{prefix}"))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                bail!("IPv6 prefix /{prefix} exceeds /128");
            }
            let seg = v6.segments();
            if seg[0] & 0xffc0 == 0xfe80 {
                bail!("link-local IPv6 (fe80::/10) not allowed in bypass list");
            }
            let bits = u128::from_be_bytes(v6.octets());
            let mask: u128 = u128::MAX << (128 - prefix);
            let net = bits & mask;
            let net_addr = std::net::Ipv6Addr::from(net.to_be_bytes());
            Ok(format!("{net_addr}/{prefix}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_simple_tunnel_name() {
        assert!(validate_interface("tun0").is_ok());
    }

    #[test]
    fn validate_accepts_dash_underscore_dot_colon() {
        // 11 chars, exercises all 4 allowed special characters (- _ . :)
        assert!(validate_interface("vpn-1_a.b:c").is_ok());
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(validate_interface("").is_err());
    }

    #[test]
    fn validate_rejects_too_long() {
        // 16 chars exceeds IFNAMSIZ-1
        assert!(validate_interface("aaaaaaaaaaaaaaaa").is_err());
    }

    #[test]
    fn validate_rejects_shell_injection_attempt() {
        assert!(validate_interface("tun0; rm -rf /").is_err());
        assert!(validate_interface("tun0\"; nft drop").is_err());
        assert!(validate_interface("tun 0").is_err()); // space
    }

    #[test]
    fn split_ips_v4_only() {
        let (v4, v6) = split_ips(&["1.2.3.4".into()]).unwrap();
        assert_eq!(v4, vec!["1.2.3.4"]);
        assert!(v6.is_empty());
    }

    #[test]
    fn split_ips_v6_only() {
        let (v4, v6) = split_ips(&["2001:db8::1".into()]).unwrap();
        assert!(v4.is_empty());
        assert_eq!(v6, vec!["2001:db8::1"]);
    }

    #[test]
    fn split_ips_preserves_order_within_family() {
        let (v4, v6) = split_ips(&[
            "1.2.3.4".into(),
            "2001:db8::1".into(),
            "5.6.7.8".into(),
            "2001:db8::2".into(),
        ])
        .unwrap();
        assert_eq!(v4, vec!["1.2.3.4", "5.6.7.8"]);
        assert_eq!(v6, vec!["2001:db8::1", "2001:db8::2"]);
    }

    #[test]
    fn split_ips_rejects_malformed() {
        assert!(split_ips(&["not-an-ip".into()]).is_err());
        assert!(split_ips(&["1.2.3.4".into(), "garbage".into()]).is_err());
        assert!(split_ips(&["256.0.0.1".into()]).is_err()); // out-of-range octet
    }

    // === bypass CIDR validation tests (Sprint 23 T1) ===

    #[test]
    fn validate_bypass_cidrs_accepts_ipv4() {
        let r = validate_bypass_cidrs(&["10.0.0.0/8".into(), "192.168.1.0/24".into()]).unwrap();
        assert_eq!(r, vec!["10.0.0.0/8", "192.168.1.0/24"]);
    }

    #[test]
    fn validate_bypass_cidrs_accepts_ipv6() {
        let r = validate_bypass_cidrs(&["2001:db8::/32".into()]).unwrap();
        assert_eq!(r, vec!["2001:db8::/32"]);
    }

    #[test]
    fn validate_bypass_cidrs_canonicalizes_host_bits_v4() {
        // 10.0.0.1/8 has host bits set — canonical form is 10.0.0.0/8.
        let r = validate_bypass_cidrs(&["10.0.0.1/8".into()]).unwrap();
        assert_eq!(r, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn validate_bypass_cidrs_canonicalizes_host_bits_v6() {
        let r = validate_bypass_cidrs(&["2001:db8:1234::5/32".into()]).unwrap();
        assert_eq!(r, vec!["2001:db8::/32"]);
    }

    #[test]
    fn validate_bypass_cidrs_rejects_missing_prefix() {
        assert!(validate_bypass_cidrs(&["10.0.0.0".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_oversize_prefix() {
        assert!(validate_bypass_cidrs(&["10.0.0.0/33".into()]).is_err());
        assert!(validate_bypass_cidrs(&["2001:db8::/129".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_prefix_zero() {
        assert!(validate_bypass_cidrs(&["1.2.3.4/0".into()]).is_err());
        assert!(validate_bypass_cidrs(&["2001:db8::/0".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_loopback_v4() {
        assert!(validate_bypass_cidrs(&["127.0.0.1/8".into()]).is_err());
        assert!(validate_bypass_cidrs(&["127.0.0.0/8".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_loopback_v6() {
        assert!(validate_bypass_cidrs(&["::1/128".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_multicast_v4() {
        assert!(validate_bypass_cidrs(&["224.0.0.1/24".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_multicast_v6() {
        assert!(validate_bypass_cidrs(&["ff02::1/16".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_link_local_v4() {
        assert!(validate_bypass_cidrs(&["169.254.1.1/16".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_link_local_v6() {
        assert!(validate_bypass_cidrs(&["fe80::1/10".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_unspecified() {
        assert!(validate_bypass_cidrs(&["0.0.0.0/8".into()]).is_err());
        assert!(validate_bypass_cidrs(&["::/64".into()]).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_exceeds_max_count() {
        let many: Vec<String> = (0..(MAX_BYPASS_CIDRS + 1))
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        assert!(validate_bypass_cidrs(&many).is_err());
    }

    #[test]
    fn validate_bypass_cidrs_rejects_duplicate_after_canonicalize() {
        // Both 10.0.0.1/8 and 10.255.255.255/8 canonicalize to 10.0.0.0/8.
        let r = validate_bypass_cidrs(&["10.0.0.1/8".into(), "10.255.255.255/8".into()]);
        assert!(
            r.is_err(),
            "expected duplicate-after-canonicalize error, got {r:?}"
        );
    }

    #[test]
    fn validate_bypass_cidrs_accepts_empty_list() {
        let r = validate_bypass_cidrs(&[]).unwrap();
        assert!(r.is_empty());
    }
}
