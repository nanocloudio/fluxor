// Names as data a module can hold at any load address.
//
// A module image is placed at a load-time address and nothing relocates it, so
// it can hold no stored address: a `const` array of `&[u8]` and a `static` that
// holds a reference become tables of absolute pointers on every target, and a
// `match` that RETURNS literals does too on 32-bit Arm, where LLVM lowers it to
// a switch lookup table of pointers (aarch64 gets PC-relative offsets). Each
// reads a wrong address at run time. `fluxor modules build` refuses an object
// that carries one.
//
// A `NameTable` keeps its strings as one run of bytes and their ends as
// integers, built at compile time, so the only address in play is the table's
// own, which code computes PC-relative. `name_table!` declares one from a list:
//
//     name_table!(PHASE_NAMES = [b"create", b"write", b"fsync"]);
//     let name: &'static [u8] = PHASE_NAMES.get(phase);

/// Byte strings indexed by position, held without pointers. `N` names, `T`
/// bytes of text in all; declare one with [`name_table!`].
pub struct NameTable<const N: usize, const T: usize> {
    text: [u8; T],
    ends: [u16; N],
}

impl<const N: usize, const T: usize> NameTable<N, T> {
    /// Build the table from `names`, which must total exactly `T` bytes.
    pub const fn new(names: [&[u8]; N]) -> Self {
        let mut text = [0u8; T];
        let mut ends = [0u16; N];
        let mut at = 0usize;
        let mut i = 0usize;
        while i < N {
            let name = names[i];
            let mut k = 0usize;
            while k < name.len() {
                text[at] = name[k];
                at += 1;
                k += 1;
            }
            assert!(
                at <= u16::MAX as usize,
                "name table text exceeds u16 offsets"
            );
            ends[i] = at as u16;
            i += 1;
        }
        assert!(at == T, "name table length does not match its text");
        NameTable { text, ends }
    }

    /// The name at `i`, or empty past the last.
    pub fn get(&'static self, i: usize) -> &'static [u8] {
        let Some(&end) = self.ends.get(i) else {
            return &[];
        };
        let start = match i.checked_sub(1) {
            Some(p) => self.ends.get(p).copied().unwrap_or(0),
            None => 0,
        };
        self.text.get(start as usize..end as usize).unwrap_or(&[])
    }
}

/// Total length of `names`, for sizing a [`NameTable`].
pub const fn name_table_len(names: &[&[u8]]) -> usize {
    let mut total = 0usize;
    let mut i = 0usize;
    while i < names.len() {
        total += names[i].len();
        i += 1;
    }
    total
}

/// Declare a `static` [`NameTable`] from a list of byte-string literals.
///
/// Textually scoped, as `define_params!` is: a consumer `include!`s the runtime
/// before invoking it.
#[allow(
    unused_macros,
    reason = "modules without a name table still include this file"
)]
macro_rules! name_table {
    ($vis:vis $name:ident = [$($s:expr),* $(,)?]) => {
        $vis static $name: NameTable<
            { [$($s as &[u8]),*].len() },
            { name_table_len(&[$($s as &[u8]),*]) },
        > = NameTable::new([$($s as &[u8]),*]);
    };
}
