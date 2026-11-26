// =============================================================================
// Native modules a host provider serves
// =============================================================================

/// The `host_lane` port-pair entry of a provider's address-control pair.
const HOST_PROVIDER_ADDR_ENTRY: &str = "NetProto:tlv16:265";

/// The channel entry of socket traffic: any `tlv16` record whole, as a lane
/// carries it (`platform::linux::host_lane`'s lane channel,
/// `fluxor_provider_net::serve::SOCKET_ENTRY`). Socket traffic crosses a
/// `host_lane` on lanes alone, never on a static pair.
const HOST_LANE_SOCKET_ENTRY: &str = "NetProto:tlv16:65538";

/// The `(tag, value)` entries of a packed params TLV
/// (`[0xFE][0x01][len u16][tag len value …][0xFF][0x00]`).
fn packed_params(tlv: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut pos = 4;
    while pos + 2 <= tlv.len() && tlv[pos] != 0xFF {
        let len = tlv[pos + 1] as usize;
        let Some(v) = tlv.get(pos + 2..pos + 2 + len) else {
            break;
        };
        out.push((tlv[pos], v));
        pos += 2 + len;
    }
    out
}

/// An instance's integer param `name`: its packed value, else the
/// manifest's default.
fn packed_u32(tlv: &[u8], manifest: &Manifest, name: &str) -> u32 {
    let Some(p) = manifest.params.iter().find(|p| p.name == name) else {
        return 0;
    };
    packed_params(tlv)
        .into_iter()
        .find(|&(t, _)| t == p.tag)
        .map_or(p.default_num, |(_, v)| {
            let mut b = [0u8; 4];
            let n = v.len().min(4);
            b[..n].copy_from_slice(&v[..n]);
            u32::from_le_bytes(b)
        })
}

/// Build every instance of a built-in a host provider serves
/// (`[host_provider]`, `linux_net`) as the `host_lane` that runs it. Its
/// lanes ([`assign_node_lanes`], marked in `is_lane`) are the node graph's
/// socket consumers and stay lane edges; every other edge into or out of
/// it is renumbered onto the lane's one static pair, which carries fixed
/// roles alone: `addr_ctl` in and `addr_evt` out. Anything else wired to
/// it is socket traffic on a static pair, refused.
///
/// The provider's argument states the instance's sizes and the contracts
/// it serves — those of its manifest no other module of the graph provides
/// ([`host_provider_serves`]); its lanes, the graph's and its workloads',
/// are reached by the module's type name, as many as its `lanes` param
/// says. The graph's validators have already run against the module's own
/// manifest.
fn realize_host_providers(
    entries: &mut [ModuleEntry],
    names: &[String],
    types: &[String],
    manifests: &HashMap<String, Manifest>,
    edges: &mut [(u16, u16, u8, u8, u8)],
    is_lane: &[bool],
    r: &ModuleResolver,
) -> Result<()> {
    for m in 0..entries.len() {
        let Some(manifest) = names.get(m).and_then(|n| manifests.get(n)) else {
            continue;
        };
        let Some(hp) = &manifest.host_provider else {
            continue;
        };
        let name = &names[m];
        let port = |p: &str| manifest.find_port_by_name(p).map(|(_, i, _)| i);
        let (addr_ctl, addr_evt) = (port("addr_ctl"), port("addr_evt"));
        let me = m as u16;
        let static_pair = |what: &str, p: u8| {
            Error::Config(format!(
                "module '{name}': {what} port {p} is not one its host provider's static pair \
                 carries: the pair carries address control alone, and socket traffic reaches \
                 it over lanes (`{name}.{LANE_COMMANDS_PORT}`, `{name}.{LANE_EVENTS_PORT}`)"
            ))
        };
        for (i, e) in edges.iter_mut().enumerate() {
            if is_lane.get(i).copied().unwrap_or(false) {
                continue;
            }
            if e.1 == me {
                if e.2 == 0 && Some(e.4) == addr_ctl {
                    e.4 = 0;
                } else {
                    return Err(static_pair("input", e.4));
                }
            }
            if e.0 == me {
                if Some(e.3) == addr_evt {
                    e.3 = 0;
                } else {
                    return Err(static_pair("output", e.3));
                }
            }
        }
        let tlv = &entries[m].params;
        let mut args = format!(
            "max_conns={} write_buf_kib={} listen_backlog={}",
            packed_u32(tlv, manifest, "max_conns"),
            packed_u32(tlv, manifest, "write_buf_kib"),
            packed_u32(tlv, manifest, "listen_backlog"),
        );
        let lanes = manifest
            .lanes
            .as_ref()
            .map_or(0, |l| packed_u32(tlv, manifest, &l.param));
        // What it serves of the graph's contracts: none another module of
        // the graph provides.
        let serves = host_provider_serves(name, names, manifests);
        args.push_str(&format!(" serves={}", serves.join(",")));
        let mut lane = json!({
            "name": name,
            "type": "host_lane",
            "runtime": hp.runtime,
            "channels": HOST_PROVIDER_ADDR_ENTRY,
            "args": args,
            // A command is never dropped: a full lane holds its producer.
            "overload": "block",
            "serves": serves.join(","),
            "lane_target": if lanes > 0 { types[m].as_str() } else { "" },
            "lanes": lanes,
        });
        if let Some(pin) = provider_pin(&hp.runtime, r.project_root())? {
            lane["runtime_digest"] = Value::String(pin);
        }
        let schema = schema::entry_schema(&lane, r)?.ok_or_else(|| {
            Error::Config(format!(
                "module '{name}': its host provider runs in a `host_lane`, which this build \
                 cannot resolve"
            ))
        })?;
        entries[m].params = pack_params_growing(&lane, &schema, None, name)?;
        entries[m].name_hash = fnv1a_hash(b"host_lane");
    }
    Ok(())
}

thread_local! {
    /// Whether the image being composed is a check ([`compose_as_check`]).
    static COMPOSING_CHECK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Whether this check has said it binds no provider.
    static CHECK_NOTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The runtime the image being composed runs on, when the composition
    /// names it ([`compose_on_runtime`]).
    static RUNTIME: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Run `f`, whose compositions are checks: each composes its graph as a run
/// would, every refusal included, but binds no host provider binary, since
/// its image is kept nowhere and the node that runs the graph composes its
/// own. A `host_lane` of a check image carries no `runtime_digest`, so no
/// runtime runs one.
pub(crate) fn compose_as_check<R>(f: impl FnOnce() -> R) -> R {
    composing(true, None, f)
}

/// Run `f`, whose compositions are images to run on this node, inside a
/// check too: a build step runs the image it composes.
pub(crate) fn compose_to_run<R>(f: impl FnOnce() -> R) -> R {
    composing(false, None, f)
}

/// Run `f`, whose compositions are images the Linux runtime at `runtime`
/// runs: each pins the providers beside that binary, the one a launch is
/// about to run, whatever project the graph resolves to.
pub(crate) fn compose_on_runtime<R>(runtime: &Path, f: impl FnOnce() -> R) -> R {
    composing(false, Some(runtime.to_path_buf()), f)
}

fn composing<R>(check: bool, runtime: Option<std::path::PathBuf>, f: impl FnOnce() -> R) -> R {
    let outer = COMPOSING_CHECK.with(|c| c.replace(check));
    let noted = CHECK_NOTED.with(|c| c.replace(false));
    let outer_runtime = RUNTIME.with(|r| r.replace(runtime));
    let r = f();
    COMPOSING_CHECK.with(|c| c.set(outer));
    CHECK_NOTED.with(|c| c.set(noted));
    RUNTIME.with(|r| r.replace(outer_runtime));
    r
}

/// The pin a node image carries for host provider `runtime`: the SHA-256,
/// hex, of the binary beside the Linux runtime the image runs on, the one
/// the composition names ([`compose_on_runtime`]), else the one this project
/// runs graphs with (`project::linux_runtime`), where `make build` builds it
/// and `fluxor sync` puts a pinned one. The `host_lane` refuses any other
/// binary. A provider not there refuses the build: an image that pins
/// nothing would run whatever lies beside the runtime. A check
/// ([`compose_as_check`]) pins nothing (`None`), and says so once.
fn provider_pin(runtime: &str, project_root: &Path) -> Result<Option<String>> {
    if COMPOSING_CHECK.with(std::cell::Cell::get) {
        if !CHECK_NOTED.with(|c| c.replace(true)) {
            println!(
                "  composed as a check: host provider `{runtime}` bound to no runtime (the node \
                 that runs the graph pins its own)"
            );
        }
        return Ok(None);
    }
    let path = RUNTIME
        .with(|r| r.borrow().clone())
        .unwrap_or_else(|| crate::project::linux_runtime(project_root))
        .with_file_name(runtime);
    let bytes = std::fs::read(&path).map_err(|e| {
        Error::Config(format!(
            "the host provider `{runtime}` is not at {} ({e}): the node image pins the \
             provider binary it runs; build it (`make build`) or sync it (`fluxor sync`)",
            path.display()
        ))
    })?;
    Ok(Some(crate::hash::hex(&crate::crypto::sha256(&bytes))))
}

/// A `host_lane` entry of the graph with the pin of the provider it runs
/// (`runtime_digest`, [`provider_pin`]; none in a check); any other entry
/// as it is. The
/// composer writes the pin: one the graph states is refused.
pub(crate) fn pin_host_lane(type_name: &str, mut module: Value, r: &ModuleResolver) -> Result<Value> {
    if type_name != "host_lane" {
        return Ok(module);
    }
    let field = |k: &str| {
        module
            .get(k)
            .or_else(|| module.get("params").and_then(|p| p.get(k)))
            .cloned()
    };
    if field("runtime_digest").is_some() {
        return Err(Error::Config(
            "a `host_lane` states `runtime_digest`, which the build writes from the provider \
             binary it runs"
                .into(),
        ));
    }
    let runtime = field("runtime")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let channels = field("channels")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    if let Some(i) = channels
        .split(';')
        .position(|c| c.trim() == HOST_LANE_SOCKET_ENTRY)
    {
        return Err(Error::Config(format!(
            "a `host_lane` states socket traffic on its static pair {i} \
             (`{HOST_LANE_SOCKET_ENTRY}`): a static pair carries fixed-role channels alone, and \
             socket traffic reaches a provider over lanes (`lanes`, `lane_target`)"
        )));
    }
    if let Some(pin) = provider_pin(&runtime, r.project_root())? {
        if let Some(obj) = module.as_object_mut() {
            obj.insert("runtime_digest".into(), Value::String(pin));
        }
    }
    Ok(module)
}
