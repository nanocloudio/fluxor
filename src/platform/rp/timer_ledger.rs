//! The RP timer ownership rules, as a function of the declared claims.
//!
//! A silicon TOML's `[kernel.timers]` names every alarm the kernel owns, on
//! the monotonic instance and on a second core's instance where the die has
//! one. The build script checks the claims with [`check`] before it
//! generates a single constant; the function is here, free of the build
//! script's I/O, so a host test drives the same rules.

/// One alarm the kernel claims: the timer instance it is on (an index the
/// caller assigns per instance name), its alarm number, and the NVIC line it
/// raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub instance: u8,
    pub alarm: u8,
    pub irq: u16,
}

/// An alarm reserved outside the kernel: the instance and alarm number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reserved {
    pub instance: u8,
    pub alarm: u8,
}

/// Why a ledger is refused. Indices are positions in the `claims` slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// An RP timer has alarms 0 to 3.
    AlarmOutOfRange { claim: usize },
    /// Two claims name one alarm of one instance.
    AlarmClaimedTwice { first: usize, second: usize },
    /// A claim names an alarm reserved outside the kernel.
    AlarmReserved { claim: usize },
    /// Two claims raise one NVIC line: neither owner could tell whose
    /// deadline fired.
    IrqShared { first: usize, second: usize },
}

/// Alarms per RP timer instance.
pub const ALARMS_PER_INSTANCE: u8 = 4;

/// Check that every claim names a real alarm, that no alarm has two owners
/// or is reserved, and that no two claims share an NVIC line, across every
/// instance at once.
pub const fn check(claims: &[Claim], reserved: &[Reserved]) -> Result<(), LedgerError> {
    let mut i = 0;
    while i < claims.len() {
        let c = claims[i];
        if c.alarm >= ALARMS_PER_INSTANCE {
            return Err(LedgerError::AlarmOutOfRange { claim: i });
        }
        let mut r = 0;
        while r < reserved.len() {
            if reserved[r].instance == c.instance && reserved[r].alarm == c.alarm {
                return Err(LedgerError::AlarmReserved { claim: i });
            }
            r += 1;
        }
        let mut j = 0;
        while j < i {
            let p = claims[j];
            if p.instance == c.instance && p.alarm == c.alarm {
                return Err(LedgerError::AlarmClaimedTwice {
                    first: j,
                    second: i,
                });
            }
            if p.irq == c.irq {
                return Err(LedgerError::IrqShared {
                    first: j,
                    second: i,
                });
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}
