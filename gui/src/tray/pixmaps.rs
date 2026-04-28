//! Rasterized tray icons for SNI `IconPixmap` delivery.
//!
//! GNOME Shell (including Ubuntu's built-in AppIndicator) does not reliably
//! honour SNI `IconThemePath` for name-based icon resolution. Shipping icons
//! as pre-rendered ARGB32 pixmaps works on every desktop environment because
//! no host-side theme lookup is involved.

use std::collections::HashMap;

use gtk4::gdk_pixbuf::Pixbuf;
use gtk4::gio::{Cancellable, MemoryInputStream};
use gtk4::glib::Bytes;
use tracing::warn;

const SIZES: &[i32] = &[22, 32];

const SVGS: &[(&str, &[u8])] = &[
    (
        "openvpn3-gui-rs-idle",
        include_bytes!("../../../data/icons/hicolor/scalable/status/openvpn3-gui-rs-idle.svg"),
    ),
    (
        "openvpn3-gui-rs-active",
        include_bytes!("../../../data/icons/hicolor/scalable/status/openvpn3-gui-rs-active.svg"),
    ),
    (
        "openvpn3-gui-rs-loading",
        include_bytes!("../../../data/icons/hicolor/scalable/status/openvpn3-gui-rs-loading.svg"),
    ),
    (
        "openvpn3-gui-rs-paused",
        include_bytes!("../../../data/icons/hicolor/scalable/status/openvpn3-gui-rs-paused.svg"),
    ),
    (
        "openvpn3-gui-rs-idle-error",
        include_bytes!(
            "../../../data/icons/hicolor/scalable/status/openvpn3-gui-rs-idle-error.svg"
        ),
    ),
];

/// Build the pixmap cache: rasterize each embedded SVG at every size in
/// `SIZES`, convert to ARGB32 network byte order, and return a map keyed by
/// the same icon name produced by `VpnTray::current_icon()`.
pub(super) fn build_pixmap_cache() -> HashMap<&'static str, Vec<ksni::Icon>> {
    let mut cache: HashMap<&'static str, Vec<ksni::Icon>> = HashMap::new();
    for (name, svg_bytes) in SVGS {
        let mut icons = Vec::with_capacity(SIZES.len());
        for &size in SIZES {
            match rasterize(svg_bytes, size) {
                Ok(icon) => icons.push(icon),
                Err(e) => warn!("Failed to rasterize {} @{}px: {}", name, size, e),
            }
        }
        if !icons.is_empty() {
            cache.insert(*name, icons);
        }
    }
    cache
}

fn rasterize(svg: &[u8], size: i32) -> Result<ksni::Icon, String> {
    let stream = MemoryInputStream::from_bytes(&Bytes::from_owned(svg.to_vec()));
    let pb = Pixbuf::from_stream_at_scale(&stream, size, size, true, None::<&Cancellable>)
        .map_err(|e| e.to_string())?;
    Ok(pixbuf_to_icon(&pb))
}

fn pixbuf_to_icon(pb: &Pixbuf) -> ksni::Icon {
    let w = pb.width();
    let h = pb.height();
    let stride = pb.rowstride() as usize;
    let n_ch = pb.n_channels() as usize;
    let has_alpha = pb.has_alpha();
    let src = pb.read_pixel_bytes();
    let src: &[u8] = src.as_ref();

    // SNI ARGB32 network byte order: memory layout is [A, R, G, B] per pixel.
    let mut data = Vec::with_capacity((w * h * 4) as usize);
    for y in 0..h as usize {
        let row_start = y * stride;
        for x in 0..w as usize {
            let px = &src[row_start + x * n_ch..];
            let r = px[0];
            let g = px[1];
            let b = px[2];
            let a = if has_alpha { px[3] } else { 0xFF };
            data.push(a);
            data.push(r);
            data.push(g);
            data.push(b);
        }
    }

    ksni::Icon {
        width: w,
        height: h,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_svgs_present() {
        assert_eq!(SVGS.len(), 5, "expected 5 status icons");
        for (name, bytes) in SVGS {
            assert!(!bytes.is_empty(), "{} is empty", name);
            let head = std::str::from_utf8(&bytes[..bytes.len().min(256)]).unwrap_or("");
            assert!(
                head.contains("<svg") || head.contains("<?xml"),
                "{} doesn't look like SVG (head: {:?})",
                name,
                &head[..head.len().min(40)]
            );
        }
    }

    #[test]
    fn every_name_maps_to_a_current_icon_branch() {
        // Every name here must be a possible return value of
        // `VpnTray::current_icon()` in src/tray/indicator.rs. If a branch is
        // added there, add its icon here.
        let names: Vec<&str> = SVGS.iter().map(|(n, _)| *n).collect();
        for expected in [
            "openvpn3-gui-rs-idle",
            "openvpn3-gui-rs-active",
            "openvpn3-gui-rs-loading",
            "openvpn3-gui-rs-paused",
            "openvpn3-gui-rs-idle-error",
        ] {
            assert!(names.contains(&expected), "missing {}", expected);
        }
    }
}
