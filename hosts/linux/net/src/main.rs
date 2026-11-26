//! `fluxor-provider-net`: serve the node's network — its control plane and,
//! when its argument names them, its host sockets — on the lane the runtime
//! started it with, or — run by hand with no lane, as
//! `fluxor-provider-net reclaim` — collect every dead instance's host
//! objects (a service manager's post-stop hook).
//!
//! `reclaim`: with `FLUXOR_INSTANCE` (or `FLUXOR_STATE_DIR`) naming the
//! instance, reports whether that tag was reclaimed. Exit 0 when it was (or
//! there was nothing to reclaim), 2 when the named instance is still live,
//! 1 on an error or a reclaim left pending.

use std::io::Write as _;

use fluxor_host_lane::provider::{self, Provider};
use fluxor_provider_net::{instance, serve};

/// Log records to the provider's stderr, which is the runtime's.
struct Stderr;

impl log::Log for Stderr {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record<'_>) {
        if self.enabled(r.metadata()) {
            let _ = writeln!(
                std::io::stderr(),
                "fluxor-provider-net: {} {}",
                r.level(),
                r.args()
            );
        }
    }
    fn flush(&self) {}
}

static LOGGER: Stderr = Stderr;

fn reclaim() -> i32 {
    use instance::Reclaimed;
    let list = |v: &[String]| {
        if v.is_empty() {
            "none".to_string()
        } else {
            v.join(" ")
        }
    };
    let mut out = std::io::stdout();
    match instance::reclaim_from_env() {
        Ok(Reclaimed::All(done)) => {
            let _ = writeln!(out, "reclaim: collected {}", list(&done));
            0
        }
        Ok(Reclaimed::Tag(tag, done)) => {
            let _ = writeln!(
                out,
                "reclaim: instance {tag} reclaimed; collected {}",
                list(&done)
            );
            0
        }
        Ok(Reclaimed::Live(tag, done)) => {
            let _ = writeln!(
                out,
                "reclaim: instance {tag} is live; collected {}",
                list(&done)
            );
            2
        }
        Ok(Reclaimed::Pending(tag, done)) => {
            let _ = writeln!(
                out,
                "reclaim: instance {tag} left pending (see the log); collected {}",
                list(&done)
            );
            1
        }
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "error: reclaim: host registry unavailable (errno {e})"
            );
            1
        }
    }
}

fn main() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !provider::lane_given() {
        if args.len() == 1 && args[0] == "reclaim" {
            std::process::exit(reclaim());
        }
        let _ = writeln!(
            std::io::stderr(),
            "usage: fluxor-provider-net reclaim (serving needs the lane a runtime starts it with)"
        );
        std::process::exit(1);
    }
    let args = match serve::Args::parse(&provider::args()) {
        Ok(a) => a,
        Err(why) => {
            let _ = provider::unable(&format!("argument refused: {why}"));
            std::process::exit(1);
        }
    };
    let mut h = match serve::Net::new(&args) {
        Ok(h) => h,
        Err(why) => {
            let _ = provider::unable(&why);
            std::process::exit(1);
        }
    };
    if let Err(why) = instance::start() {
        let _ = provider::unable(&why);
        std::process::exit(1);
    }
    let mut p = match Provider::connect(
        &serve::lane_identity(&args.contracts, args.ports()),
        fluxor_host_lane::ABI_SURFACE_DIGEST,
    ) {
        Ok(p) => p,
        Err(e) => {
            log::error!("{e}");
            std::process::exit(2);
        }
    };
    instance::set_incarnation(&p.incarnation());
    serve::start();
    let r = p.serve(&mut h);
    // The lane ended: the node's network goes with it.
    instance::shutdown();
    if let Err(e) = r {
        log::error!("{e}");
        std::process::exit(1);
    }
}
