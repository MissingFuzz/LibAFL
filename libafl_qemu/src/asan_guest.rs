#![allow(clippy::cast_possible_wrap)]

use std::{
    env,
    fmt::{self, Debug, Formatter},
    fs,
    path::PathBuf,
};

use libafl::{inputs::UsesInput, state::HasMetadata};

use crate::{
    emu::{EmuError, MemAccessInfo},
    helper::{
        HasInstrumentationFilter, IsFilter, QemuHelper, QemuHelperTuple,
        QemuInstrumentationAddressRangeFilter,
    },
    hooks::{Hook, QemuHooks},
    sys::{libafl_tcg_gen_asan, TCGTemp},
    GuestAddr, MapInfo, Qemu
};

static mut ASAN_GUEST_INITED: bool = false;

pub fn init_qemu_with_asan_guest(
    args: &mut Vec<String>,
    env: &mut [(String, String)],
) -> Result<(Qemu, String), EmuError> {
    let current = env::current_exe().unwrap();
    let asan_lib = fs::canonicalize(current)
        .unwrap()
        .parent()
        .unwrap()
        .join("libgasan.so");

    let asan_lib = env::var_os("CUSTOM_ASAN_PATH")
        .map(|x| PathBuf::from(x.to_string_lossy().to_string()))
        .unwrap_or(asan_lib);

    if !asan_lib.as_path().exists() {
        panic!("The ASAN library doesn't exist: {asan_lib:#?}")
    }

    let asan_lib = asan_lib
        .to_str()
        .expect("The path to the asan lib is invalid")
        .to_string();

    println!("Loading ASAN: {asan_lib:}");

    let add_asan =
        |e: &str| "LD_PRELOAD=".to_string() + &asan_lib + " " + &e["LD_PRELOAD=".len()..];

    let mut added = false;
    for (k, v) in &mut *env {
        if k == "QEMU_SET_ENV" {
            let mut new_v = vec![];
            for e in v.split(',') {
                if e.starts_with("LD_PRELOAD=") {
                    added = true;
                    new_v.push(add_asan(e));
                } else {
                    new_v.push(e.to_string());
                }
            }
            *v = new_v.join(",");
        }
    }
    for i in 0..args.len() {
        if args[i] == "-E" && i + 1 < args.len() && args[i + 1].starts_with("LD_PRELOAD=") {
            added = true;
            args[i + 1] = add_asan(&args[i + 1]);
        }
    }

    if !added {
        args.insert(1, "LD_PRELOAD=".to_string() + &asan_lib);
        args.insert(1, "-E".into());
    }

    if env::var("QASAN_DEBUG").is_ok() {
        args.push("-E".into());
        args.push("QASAN_DEBUG=1".into());
    }

    if env::var("QASAN_LOG").is_ok() {
        args.push("-E".into());
        args.push("QASAN_LOG=1".into());
    }

    unsafe {
        ASAN_GUEST_INITED = true;
    }

    let qemu = Qemu::init(args, env)?;
    Ok((qemu, asan_lib))
}

#[derive(Clone)]
struct QemuAsanGuestMapping {
    start: GuestAddr,
    end: GuestAddr,
    path: String,
}

impl Debug for QemuAsanGuestMapping {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}-0x{:016x} {}", self.start, self.end, self.path)
    }
}

impl From<&MapInfo> for QemuAsanGuestMapping {
    fn from(map: &MapInfo) -> QemuAsanGuestMapping {
        let path = map.path().map(|p| p.to_string()).unwrap_or_default();
        let start = map.start();
        let end = map.end();
        QemuAsanGuestMapping { start, end, path }
    }
}

#[derive(Debug)]
pub struct QemuAsanGuestHelper {
    filter: QemuInstrumentationAddressRangeFilter,
    mappings: Vec<QemuAsanGuestMapping>,
}

#[cfg(any(feature = "aarch64", feature = "x86_64", feature = "clippy"))]
impl QemuAsanGuestHelper {
    const HIGH_SHADOW_START: GuestAddr = 0x02008fff7000;
    const HIGH_SHADOW_END: GuestAddr = 0x10007fff7fff;
    const LOW_SHADOW_START: GuestAddr = 0x00007fff8000;
    const LOW_SHADOW_END: GuestAddr = 0x00008fff6fff;
}

#[cfg(any(feature = "arm", feature = "i386", feature = "mips", feature = "ppc"))]
impl QemuAsanGuestHelper {
    const HIGH_SHADOW_START: GuestAddr = 0x28000000;
    const HIGH_SHADOW_END: GuestAddr = 0x3fffffff;
    const LOW_SHADOW_START: GuestAddr = 0x20000000;
    const LOW_SHADOW_END: GuestAddr = 0x23ffffff;
}

impl QemuAsanGuestHelper {
    #[must_use]
    pub fn default(qemu: &Qemu, asan: String) -> Self {
        Self::new(qemu, asan, QemuInstrumentationAddressRangeFilter::None)
    }

    #[must_use]
    pub fn new(
        qemu: &Qemu,
        asan: String,
        filter: QemuInstrumentationAddressRangeFilter,
    ) -> Self {
        for mapping in qemu.mappings() {
            let start = mapping.start();
            let end = mapping.end();
            let path = mapping.path().unwrap_or_default();
            println!("MapInfo: 0x{start:016x}-0x{end:016x} {path:}");
        }

        let mappings = qemu
            .mappings()
            .map(|m| QemuAsanGuestMapping::from(&m))
            .collect::<Vec<QemuAsanGuestMapping>>();

        for mapping in mappings.iter() {
            println!("QemuAsanGuestMapping: {mapping:#?}");
        }

        let hi_start = Self::HIGH_SHADOW_START;
        let hi_end = Self::HIGH_SHADOW_END;
        mappings
            .iter()
            .find(|m| m.start <= hi_start && m.end > hi_end)
            .expect(format!("HighShadow 0x{hi_start:016x}-0x{hi_end:016x} not found, confirm ASAN DSO is loaded in the guest").as_str());

        let lo_start = Self::LOW_SHADOW_START;
        let lo_end = Self::LOW_SHADOW_END;
        mappings
            .iter()
            .find(|m| m.start <= lo_start && m.end > lo_end)
            .expect(format!("LowShadow 0x{lo_start:016x}-0x{lo_end:016x} not found, confirm ASAN DSO is loaded in the guest").as_str());

        let mappings = mappings
            .iter()
            .filter(|m| m.path == asan)
            .cloned()
            .collect::<Vec<QemuAsanGuestMapping>>();

        for mapping in mappings.iter() {
            println!("asan mapping: {mapping:#?}");
        }

        Self { filter, mappings }
    }

    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }
}

impl<S: UsesInput> HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter, S> for QemuAsanGuestHelper {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.filter
    }
}

fn gen_readwrite_guest_asan<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    addr: *mut TCGTemp,
    info: MemAccessInfo,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let h = hooks.match_helper_mut::<QemuAsanGuestHelper>().unwrap();
    if !h.must_instrument(pc) {
        return None;
    }

    /* Don't sanitize the sanitizer! */
    if h.mappings.iter().any(|m| m.start <= pc && pc < m.end) {
        return None;
    }

    let size = info.size();

    /* TODO - If our size is > 8 then do things via a runtime callback */
    if size > 8 {
        panic!("I shouldn't be here!");
    }

    unsafe {
        libafl_tcg_gen_asan(addr, size);
    }

    None
}

fn guest_trace_error_asan<QT, S>(
    _hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    _addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    panic!("I really shouldn't be here");
}

fn guest_trace_error_n_asan<QT, S>(
    _hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    _addr: GuestAddr,
    _n: usize,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    panic!("I really shouldn't be here either");
}

impl<S> QemuHelper<S> for QemuAsanGuestHelper
where
    S: UsesInput + HasMetadata,
{
    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.reads(
            Hook::Function(gen_readwrite_guest_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_n_asan::<QT, S>),
        );

        hooks.writes(
            Hook::Function(gen_readwrite_guest_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_asan::<QT, S>),
            Hook::Function(guest_trace_error_n_asan::<QT, S>),
        );
    }
}
