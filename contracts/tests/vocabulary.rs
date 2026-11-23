//! The content-type positions, the positional vocabulary tables and the
//! per-fact comparison rules (`fluxor_contracts::vocabulary`).
//!
//! Run with:
//!   cargo test -p fluxor-contracts --test vocabulary

use fluxor_contracts::vocabulary::*;
use fluxor_contracts::{Framing, RateClass, CONTENT_FRAMING, CONTENT_RATE_CLASS, CONTENT_TYPES};

fn position(name: &str) -> usize {
    CONTENT_TYPES
        .iter()
        .position(|n| *n == name)
        .unwrap_or_else(|| panic!("{name}"))
}

#[test]
fn the_drawn_ui_content_types_hold_their_bytes() {
    assert_eq!(position("VideoRaster"), 0x06);
    assert_eq!(position("VideoDraw"), 0x12);
    assert_eq!(position("MeasurementStream"), 0x27);
    for (name, byte) in [
        ("TextEvents", 0x28),
        ("AccessibilityTree", 0x29),
        ("AccessibilityActions", 0x2A),
    ] {
        assert_eq!(position(name), byte, "{name}");
        assert_eq!(CONTENT_RATE_CLASS[byte], RateClass::Control, "{name}");
        assert_eq!(CONTENT_FRAMING[byte], Framing::Streamed, "{name}");
    }
    assert_eq!(CONTENT_TYPES.len(), 0x2B);
    assert_eq!(CONTENT_FRAMING[position("VideoDraw")], Framing::Streamed);
    assert_eq!(CONTENT_FRAMING[position("VideoRaster")], Framing::Streamed);
}

#[test]
fn record_stream_surfaces_are_port_scoped() {
    for (content_type, capability) in [
        ("VideoDraw", "video.draw"),
        ("VideoRaster", "video.raster"),
        ("TextEvents", "input.text"),
        ("AccessibilityTree", "accessibility.tree"),
    ] {
        assert_eq!(surface_capability(content_type), Some(capability));
        assert!(CAPABILITY_NAMES.contains(&capability), "{capability}");
        assert!(
            PORT_SCOPED_CAPABILITIES.contains(&capability),
            "{capability}"
        );
    }
    // Fixed records from one producer: no surface capability.
    assert_eq!(surface_capability("AccessibilityActions"), None);
    // The text surface carries no facts; the contract fixes its limit.
    assert!(facts_for("input.text").is_none());
}

#[test]
fn positional_tables_hold_their_order() {
    assert_eq!(RASTER_FORMATS, &["rgb565", "rgba8"]);
    assert_eq!(PIXMAP_FORMATS, &["rgba8", "rgb565"]);
    assert_eq!(
        DRAW_OPS,
        &[
            "fill_rect",
            "fill_rrect",
            "border",
            "pixmap",
            "glyphs",
            "clip_rect",
            "clip_rrect",
            "translate",
            "surface",
            "res_ref"
        ]
    );
    assert_eq!(raster_format_byte("rgba8"), Some(1));
    assert_eq!(pixmap_format_byte("rgba8"), Some(0));
    assert_eq!(draw_op_bit("res_ref"), Some(9));
    assert_eq!(draw_op_bit("fill_path"), None);
}

#[test]
fn access_roles_hold_their_order() {
    const EXPECTED: &[&str] = &[
        "generic",
        "button",
        "checkbox",
        "radio",
        "radiogroup",
        "switch",
        "slider",
        "spinbutton",
        "textbox",
        "searchbox",
        "combobox",
        "listbox",
        "option",
        "link",
        "heading",
        "paragraph",
        "list",
        "listitem",
        "img",
        "group",
        "region",
        "dialog",
        "alertdialog",
        "alert",
        "status",
        "menu",
        "menubar",
        "menuitem",
        "menuitemcheckbox",
        "menuitemradio",
        "tab",
        "tablist",
        "tabpanel",
        "progressbar",
        "meter",
        "toolbar",
        "separator",
        "scrollbar",
        "table",
        "row",
        "cell",
        "columnheader",
        "rowheader",
        "grid",
        "gridcell",
        "tree",
        "treeitem",
    ];
    assert_eq!(ACCESS_ROLES, EXPECTED);
    assert_eq!(access_role_byte("generic"), Some(0));
    assert_eq!(access_role_byte("treeitem"), Some(46));
    let mut sorted = ACCESS_ROLES.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ACCESS_ROLES.len(), "a role is listed twice");
}

#[test]
fn the_draw_and_raster_facts_are_declared() {
    let names = |cap: &str| -> Vec<&str> {
        facts_for(cap)
            .unwrap()
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names("video.draw"),
        [
            "ops",
            "pixmap_formats",
            "glyph_formats",
            "max_depth",
            "max_resources",
            "resource_bytes",
            "frame_bytes",
            "band_rows",
            "damage",
            "atomic",
            "refresh_mhz",
            "surfaces"
        ]
    );
    assert_eq!(
        names("video.raster"),
        ["formats", "regions", "width", "height"]
    );
    assert_eq!(names("accessibility.tree"), ["max_nodes"]);
    let values = |cap: &str, fact: &str| {
        facts_for(cap)
            .unwrap()
            .iter()
            .find(|(n, _)| *n == fact)
            .map(|(_, v)| *v)
            .unwrap()
    };
    assert_eq!(values("video.draw", "ops"), DRAW_OPS);
    assert_eq!(values("video.draw", "pixmap_formats"), PIXMAP_FORMATS);
    assert_eq!(values("video.draw", "glyph_formats"), GLYPH_FORMATS);
    assert_eq!(values("video.draw", "damage"), &["full", "partial"]);
    assert_eq!(values("video.draw", "atomic"), &["yes", "no"]);
    assert_eq!(values("video.raster", "formats"), RASTER_FORMATS);
    assert_eq!(values("video.raster", "regions"), &["damage", "bands"]);
}

#[test]
fn every_numeric_fact_has_exactly_one_rule() {
    let mut numeric: Vec<&str> = Vec::new();
    for (capability, facts) in CAPABILITY_FACTS {
        for (fact, admitted) in *facts {
            if *admitted == FACT_NUMERIC {
                assert!(
                    NUMERIC_FACT_RULES.iter().any(|(n, _)| n == fact),
                    "numeric fact `{fact}` on `{capability}` has no row in NUMERIC_FACT_RULES"
                );
                assert!(fact_is_numeric(capability, fact));
                numeric.push(fact);
            } else {
                assert_eq!(fact_rule(fact, admitted), FactRule::Subset, "{fact}");
            }
        }
    }
    for (i, (fact, rule)) in NUMERIC_FACT_RULES.iter().enumerate() {
        assert!(
            numeric.contains(fact),
            "NUMERIC_FACT_RULES names `{fact}`, which no capability declares"
        );
        assert!(
            !NUMERIC_FACT_RULES[..i].iter().any(|(n, _)| n == fact),
            "`{fact}` has two rows"
        );
        assert_ne!(*rule, FactRule::Subset, "{fact}");
        assert_eq!(fact_rule(fact, FACT_NUMERIC), *rule);
    }
}

#[test]
fn each_numeric_fact_compares_by_its_rule() {
    use FactRule::{Ceiling, Exact, Floor};
    for (fact, rule) in [
        ("max_payload", Ceiling),
        ("clock_rate", Exact),
        ("channels", Exact),
        ("samples_per_channel", Exact),
        ("period_ms", Exact),
        ("max_depth", Ceiling),
        ("max_resources", Ceiling),
        ("resource_bytes", Ceiling),
        ("frame_bytes", Ceiling),
        ("band_rows", Ceiling),
        ("refresh_mhz", Floor),
        ("surfaces", Ceiling),
        ("width", Ceiling),
        ("height", Ceiling),
        ("max_nodes", Ceiling),
    ] {
        assert_eq!(fact_rule(fact, FACT_NUMERIC), rule, "{fact}");
    }
    assert_eq!(NUMERIC_FACT_RULES.len(), 15);
    // An enumerated fact is a subset whatever its name.
    assert_eq!(fact_rule("max_payload", &["a", "b"]), FactRule::Subset);
}

#[test]
fn the_banding_rule_reads_the_consumers_frame_bytes() {
    assert_eq!(
        (BANDING.capability, BANDING.fact, BANDING.gate),
        ("video.draw", "band_rows", "frame_bytes")
    );
    assert_eq!(cross_fact_rule("video.draw", "band_rows"), Some(&BANDING));
    assert_eq!(cross_fact_rule("video.draw", "frame_bytes"), None);
    assert_eq!(cross_fact_rule("video.raster", "band_rows"), None);
    for rule in CROSS_FACT_RULES {
        let facts = facts_for(rule.capability).unwrap();
        for fact in [rule.fact, rule.gate] {
            assert!(fact_is_numeric(rule.capability, fact), "{fact}");
            assert!(facts.iter().any(|(n, _)| *n == fact));
        }
    }
    // A consumer that retains, or says nothing, takes any stream.
    for producer in [None, Some(0), Some(16), Some(400)] {
        assert!(banding_admits(None, producer, Some(16)));
        assert!(banding_admits(Some(8192), producer, Some(16)));
        assert!(banding_admits(Some(8192), producer, None));
    }
    // One that retains nothing needs bands it can hold.
    assert!(!banding_admits(Some(0), None, Some(16)));
    assert!(!banding_admits(Some(0), Some(0), Some(16)));
    assert!(banding_admits(Some(0), Some(8), Some(16)));
    assert!(banding_admits(Some(0), Some(16), Some(16)));
    assert!(!banding_admits(Some(0), Some(17), Some(16)));
    assert!(banding_admits(Some(0), Some(17), None));
}

#[test]
fn counter_capabilities_are_target_provided() {
    for cap in ["counter.cycles", "counter.icache"] {
        assert!(TARGET_CAPABILITIES.contains(&cap));
        assert!(CAPABILITY_NAMES.contains(&cap));
        assert!(!PORT_SCOPED_CAPABILITIES.contains(&cap));
    }
    assert!(!fact_is_numeric("counter.cycles", "clock"));
}
