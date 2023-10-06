//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
#[cfg(feature = "i386")]
use core::mem::size_of;
use core::time::Duration;
use std::{env, fs::DirEntry, io, path::PathBuf, process, ptr::addr_of_mut};

use clap::{builder::Str, Parser};
use libafl::{
    corpus::{Corpus, CorpusId, NopCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig, EventRestarter},
    executors::{ExitKind, TimeoutExecutor},
    feedbacks::MaxMapFeedback,
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, VariableMapObserver},
    prelude::LlmpRestartingEventManager,
    schedulers::QueueScheduler,
    stages::{MapEqualityFactory, StagesTuple, StdTMinMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice,
};
use libafl_qemu::{
    edges::{edges_map_mut_slice, MAX_EDGES_NUM},
    elf::EasyElf,
    emu::Emulator,
    ArchExtras, CallingConvention, GuestAddr, GuestReg, MmapPerms, QemuEdgeCoverageHelper,
    QemuExecutor, QemuHooks, Regs,
};

#[derive(Default)]
pub struct Version;

impl From<Version> for Str {
    fn from(_: Version) -> Str {
        let version = [
            ("Architecture:", env!("CPU_TARGET")),
            ("Build Timestamp:", env!("VERGEN_BUILD_TIMESTAMP")),
            ("Describe:", env!("VERGEN_GIT_DESCRIBE")),
            ("Commit SHA:", env!("VERGEN_GIT_SHA")),
            ("Commit Date:", env!("VERGEN_RUSTC_COMMIT_DATE")),
            ("Commit Branch:", env!("VERGEN_GIT_BRANCH")),
            ("Rustc Version:", env!("VERGEN_RUSTC_SEMVER")),
            ("Rustc Channel:", env!("VERGEN_RUSTC_CHANNEL")),
            ("Rustc Host Triple:", env!("VERGEN_RUSTC_HOST_TRIPLE")),
            ("Rustc Commit SHA:", env!("VERGEN_RUSTC_COMMIT_HASH")),
            ("Cargo Target Triple", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        ]
        .iter()
        .map(|(k, v)| format!("{k:25}: {v}\n"))
        .collect::<String>();

        format!("\n{version:}").into()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("qemu_tmin-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Tool for test case minimization using QEMU instrumentation"
)]
pub struct FuzzerOptions {
    #[arg(long, help = "Output directory")]
    output: String,

    #[arg(long, help = "Input directory")]
    input: String,

    #[arg(long, help = "Timeout in seconds", default_value_t = 1_u64)]
    timeout: u64,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    cores: Cores,

    #[arg(
        long,
        help = "Number of iterations for minimization",
        default_value_t = 1024_usize
    )]
    iterations: usize,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

pub fn fuzz() {
    let mut options = FuzzerOptions::parse();

    let corpus_dir = PathBuf::from(options.input);

    let corpus_files = corpus_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .collect::<Result<Vec<DirEntry>, io::Error>>()
        .expect("Failed to read dir entry");

    let num_files = corpus_files.len();
    let num_cores = options.cores.ids.len();
    let files_per_core = (num_files as f64 / num_cores as f64).ceil() as usize;

    let program = env::args().next().unwrap();
    log::debug!("Program: {program:}");

    options.args.insert(0, program);
    log::debug!("ARGS: {:#?}", options.args);

    env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&options.args, &env).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    log::debug!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    emu.entry_break(test_one_input_ptr);

    for m in emu.mappings() {
        log::debug!(
            "Mapping: 0x{:016x}-0x{:016x}, {}",
            m.start(),
            m.end(),
            m.path().unwrap_or("<EMPTY>")
        );
    }

    let pc: GuestReg = emu.read_reg(Regs::Pc).unwrap();
    log::debug!("Break at {pc:#x}");

    let ret_addr: GuestAddr = emu.read_return_address().unwrap();
    log::debug!("Return address = {ret_addr:#x}");

    emu.set_breakpoint(ret_addr);

    let input_addr = emu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    log::debug!("Placing input at {input_addr:#x}");

    let stack_ptr: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    let reset = |buf: &[u8], len: GuestReg| -> Result<(), String> {
        unsafe {
            emu.write_mem(input_addr, buf);
            emu.write_reg(Regs::Pc, test_one_input_ptr)?;
            emu.write_reg(Regs::Sp, stack_ptr)?;
            emu.write_return_address(ret_addr)?;
            emu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)?;
            emu.write_function_argument(CallingConvention::Cdecl, 1, len)?;
            emu.run();
            Ok(())
        }
    };

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;
        reset(buf, len).unwrap();
        ExitKind::Ok
    };

    let mut run_client = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, core_id| {
        let core_idx = options
            .cores
            .position(core_id)
            .expect("Failed to get core index");
        let files = corpus_files
            .iter()
            .skip(files_per_core * core_idx)
            .take(files_per_core)
            .map(|x| x.path())
            .collect::<Vec<PathBuf>>();

        if files.is_empty() {
            mgr.send_exiting()?;
            Err(Error::ShuttingDown)?
        }

        let edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM),
            ))
        };

        let feedback_factory = MapEqualityFactory::with_observer(&edges_observer);
        let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

        #[allow(clippy::let_unit_value)]
        let mut objective = ();

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                OnDiskCorpus::new(PathBuf::from(options.output.clone())).unwrap(),
                NopCorpus::new(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut hooks = QemuHooks::new(&emu, tuple_list!(QemuEdgeCoverageHelper::default()));

        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create QemuExecutor");

        let mut executor = TimeoutExecutor::new(executor, Duration::from_secs(options.timeout));

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs_by_filenames(&mut fuzzer, &mut executor, &mut mgr, &files)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dir);
                    process::exit(0);
                });
            log::debug!("We imported {} inputs from disk.", state.corpus().count());
        }

        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdTMinMutationalStage::new(
            mutator,
            feedback_factory,
            options.iterations
        ));

        stages.perform_all(
            &mut fuzzer,
            &mut executor,
            &mut state,
            &mut mgr,
            CorpusId::from(0_usize),
        )?;

        log::debug!("Processed {} inputs from disk.", files.len());

        mgr.send_exiting()?;
        Err(Error::ShuttingDown)?
    };

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new().expect("Failed to init shared memory"))
        .broker_port(options.port)
        .configuration(EventConfig::from_build_id())
        .monitor(MultiMonitor::new(|s| println!("{s}")))
        .run_client(&mut run_client)
        .cores(&options.cores)
        .stdout_file(if options.verbose {
            None
        } else {
            Some("/dev/null")
        })
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Run finished successfully."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
