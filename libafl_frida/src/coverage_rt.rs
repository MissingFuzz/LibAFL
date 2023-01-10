//! Functionality regarding binary-only coverage collection.
use core::ptr::addr_of_mut;
use std::{cell::RefCell, collections::HashMap, marker::PhantomPinned, pin::Pin, rc::Rc};

#[cfg(target_arch = "x86_64")]
use capstone::arch::{
    x86::{
        X86Insn::{self, X86_INS_CALL, X86_INS_JMP, X86_INS_RET},
        X86OperandType::Imm,
    },
    ArchOperand::X86Operand,
};
use capstone::{
    arch::{self, BuildsCapstone},
    Capstone,
};
#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{
        arm64::{
            Arm64CC::ARM64_CC_AL,
            Arm64Insn::{
                self, ARM64_INS_B, ARM64_INS_BL, ARM64_INS_RET, ARM64_INS_RETAA, ARM64_INS_RETAB,
            },
        },
        DetailsArchInsn,
    },
    prelude::ArchDetail::Arm64Detail,
};
#[cfg(target_arch = "aarch64")]
use dynasmrt::DynasmLabelApi;
use dynasmrt::{dynasm, DynasmApi};
use frida_gum::{
    instruction_writer::InstructionWriter,
    stalker::{StalkerObserver, StalkerOutput},
};
use libafl::bolts::xxh3_rrmxmx_mixer;
use rangemap::RangeMap;

use crate::helper::FridaRuntime;

/// (Default) map size for frida coverage reporting
pub const MAP_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct CoverageRuntimeInner {
    map: [u8; MAP_SIZE],
    previous_pc: u64,
    observer: CoverageObserver,
    _pinned: PhantomPinned,
}

/// Frida binary-only coverage
#[derive(Debug)]
pub struct CoverageRuntime(Pin<Rc<RefCell<CoverageRuntimeInner>>>);

impl Default for CoverageRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl FridaRuntime for CoverageRuntime {
    /// Initialize the coverage runtime
    /// The struct MUST NOT be moved after this function is called, as the generated assembly references it
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        _modules_to_instrument: &[&str],
    ) {
    }

    fn pre_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        _input: &I,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn post_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        _input: &I,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl CoverageRuntime {
    /// Create a new coverage runtime
    #[must_use]
    pub fn new() -> Self {
        Self(Rc::pin(RefCell::new(CoverageRuntimeInner {
            map: [0_u8; MAP_SIZE],
            previous_pc: 0,
            observer: CoverageObserver::new(),
            _pinned: PhantomPinned,
        })))
    }

    /// Retrieve the coverage map pointer
    pub fn map_mut_ptr(&mut self) -> *mut u8 {
        self.0.borrow_mut().map.as_mut_ptr()
    }

    /// Retrieve the coverage observer
    pub fn observer(&mut self) -> &mut CoverageObserver {
        unsafe { &mut *addr_of_mut!(self.0.borrow_mut().observer) }
    }

    /// A minimal `maybe_log` implementation. We insert this into the transformed instruction stream
    /// every time we need a copy that is within a direct branch of the start of the transformed basic
    /// block.
    #[cfg(target_arch = "aarch64")]
    pub fn generate_inline_code(&mut self, h64: u64) -> Box<[u8]> {
        let mut borrow = self.0.borrow_mut();
        let prev_loc_ptr = addr_of_mut!(borrow.previous_pc);
        let map_addr_ptr = addr_of_mut!(borrow.map);
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        dynasm!(ops
            ;   .arch aarch64
            // Store the context
            ;   stp x0, x1, [sp, #-0xa0]

            // Load the previous_pc
            ;   ldr x1, >previous_loc
            ;   ldr x1, [x1]

            // Caltulate the edge id
            ;   ldr x0, >loc
            ;   eor x0, x1, x0

            // Load the map byte address
            ;   ldr x1, >map_addr
            ;   add x0, x1, x0

            // Update the map byte
            ;   ldrb w1, [x0]
            ;   add w1, w1, #1
            ;   add x1, x1, x1, lsr #8
            ;   strb w1, [x0]

            // Update the previous_pc value
            ;   ldr x0, >loc_shr
            ;   ldr x1, >previous_loc
            ;   str x0, [x1]

            // Restore the context
            ;   ldp x0, x1, [sp, #-0xa0]

            // Skip the data
            ;   b >end

            ;map_addr:
            ;.qword map_addr_ptr as i64
            ;previous_loc:
            ;.qword prev_loc_ptr as i64
            ;loc:
            ;.qword h64 as i64
            ;loc_shr:
            ;.qword (h64 >> 1) as i64
            ;   ldp x16, x17, [sp], #0x90
            ;end:
        );
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len()].to_vec().into_boxed_slice()
    }

    /// Write inline instrumentation for coverage
    #[cfg(target_arch = "x86_64")]
    pub fn generate_inline_code(&mut self, h64: u64) -> Box<[u8]> {
        let mut borrow = self.0.borrow_mut();
        let prev_loc_ptr = addr_of_mut!(borrow.previous_pc);
        let map_addr_ptr = addr_of_mut!(borrow.map);
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        dynasm!(ops
            ;   .arch x64
            // Store the context
            ; mov    QWORD [rsp-0x88], rax
            ; lahf
            ; mov    QWORD [rsp-0x90], rax
            ; mov    QWORD [rsp-0x98], rbx

            // Load the previous_pc
            ; mov rax, QWORD prev_loc_ptr as *mut u64 as _
            ; mov rax, QWORD [rax]

            // Calculate the edge id
            ; mov ebx, WORD h64 as i32
            ; xor rax, rbx

            // Load the map byte address
            ; mov rbx, QWORD map_addr_ptr as *mut [u8; MAP_SIZE] as _
            ; add rax, rbx

            // Update the map byte
            ; mov bl, BYTE [rax]
            ; add bl,0x1
            ; adc bl,0x0
            ; mov BYTE [rax],bl

            // Update the previous_pc value
            ; mov rax, QWORD prev_loc_ptr as *mut u64 as _
            ; mov ebx, WORD (h64 >> 1) as i32
            ; mov QWORD [rax], rbx

            // Restore the context
            ; mov    rbx, QWORD [rsp-0x98]
            ; mov    rax, QWORD [rsp-0x90]
            ; sahf
            ; mov    rax, QWORD [rsp-0x88]
        );
        let ops_vec = ops.finalize().unwrap();

        ops_vec[..ops_vec.len()].to_vec().into_boxed_slice()
    }

    /// Emits coverage mapping into the current basic block.
    #[inline]
    pub fn emit_coverage_mapping(&mut self, address: u64, output: &StalkerOutput) {
        let h64 = xxh3_rrmxmx_mixer(address);
        let writer = output.writer();
        let code = self.generate_inline_code(h64 & (MAP_SIZE as u64 - 1));
        self.0.borrow_mut().observer.insert(writer.pc(), code.len());
        writer.put_bytes(&code);
    }
}

/// Type to be used as a StalkerObserver for modifying the target address when
/// stalker calls the callback to determine the next block to be executed
/// following a branch.
#[derive(Debug)]
pub struct CoverageObserver {
    blocks: HashMap<u64, usize>,
    cache: HashMap<u64, bool>,
}

impl CoverageObserver {
    /// Create a new coverage observer
    pub fn new() -> CoverageObserver {
        Self {
            blocks: HashMap::<u64, usize>::new(),
            cache: HashMap::<u64, bool>::new(),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn is_deterministric_branch<'a>(&self, from_insn: u64) -> bool {
        if let Ok(cs) = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
        {
            let bytes = unsafe { std::slice::from_raw_parts(from_insn as *const u8, 4) };
            if let Ok(insns) = cs.disasm_count(bytes, from_insn, 1) {
                if let Some(first) = insns.first() {
                    if let Ok(detail) = cs.insn_detail(&first) {
                        if let Arm64Detail(arch_detail) = detail.arch_detail() {
                            match Arm64Insn::from(first.id().0) {
                                ARM64_INS_B | ARM64_INS_BL => {
                                    return arch_detail.cc() == ARM64_CC_AL;
                                }
                                ARM64_INS_RET | ARM64_INS_RETAA | ARM64_INS_RETAB => {
                                    return arch_detail.operands().len() == 0;
                                }
                                _ => return false,
                            }
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(target_arch = "x86_64")]
    fn is_deterministric_branch<'a>(&self, from_insn: u64) -> bool {
        if let Ok(cs) = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
        {
            let bytes = unsafe { std::slice::from_raw_parts(from_insn as *const u8, 16) };
            if let Ok(insns) = cs.disasm_count(bytes, from_insn, 1) {
                if let Some(first) = insns.first() {
                    if let Ok(detail) = cs.insn_detail(&first) {
                        let arch_detail = detail.arch_detail();
                        let ops = arch_detail.operands();

                        match X86Insn::from(first.id().0) {
                            X86_INS_CALL | X86_INS_JMP => {
                                if let Some(op1) = ops.first() {
                                    if let X86Operand(xop) = op1 {
                                        if let Imm(_) = xop.op_type {
                                            return true;
                                        }
                                    }
                                }
                                return false;
                            }
                            X86_INS_RET => return true,
                            _ => return false,
                        }
                    }
                }
            }
        }
        false
    }

    /// Notify the coverage observer of a new block of inserted inline coverage
    /// instrumentation code
    pub fn insert(&mut self, address: u64, size: usize) {
        self.blocks.insert(address, size);
    }
}

impl StalkerObserver for CoverageObserver {
    fn notify_backpatch(
        &mut self,
        _backpatch: *const frida_gum_sys::GumBackpatch,
        _size: frida_gum_sys::gsize,
    ) {
    }

    fn switch_callback(
        &mut self,
        from_address: frida_gum_sys::gpointer,
        _start_address: frida_gum_sys::gpointer,
        from_insn: frida_gum_sys::gpointer,
        target: &mut frida_gum_sys::gpointer,
    ) {
        if from_address == std::ptr::null_mut() {
            return;
        }

        let deterministic = if let Some(x) = self.cache.get(&(from_insn as u64)) {
            *x
        } else {
            let x = self.is_deterministric_branch(from_insn as u64);
            self.cache.insert(from_insn as u64, x);
            x
        };

        if !deterministic {
            return;
        }

        let tgt = unsafe { &mut *(target as *mut frida_gum_sys::gpointer as *mut u64) };
        if let Some(size) = self.blocks.get(tgt) {
            #[cfg(target_arch = "x86_64")]
            {
                *tgt += *size as u64;
            }
            #[cfg(target_arch = "aarch64")]
            {
                *tgt += (*size - 4) as u64;
            }
        }
    }
}
