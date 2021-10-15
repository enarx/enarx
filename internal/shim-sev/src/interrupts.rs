// SPDX-License-Identifier: Apache-2.0

//! Interrupt handling

use crate::addr::SHIM_VIRT_OFFSET;
use crate::debug::print_stack_trace;
use crate::eprintln;
use crate::hostcall::shim_exit;
use crate::idt::{InterruptDescriptorTable, InterruptStackFrame};
use crate::payload::PAYLOAD_VIRT_ADDR;
use crate::snp::cpuid_count;

use core::mem::size_of;

use spinning::Lazy;
use x86_64::structures::idt::PageFaultErrorCode;
use xsave::XSave;

/// size of area reserved for xsave
pub const XSAVE_AREA_SIZE: u32 = size_of::<XSave>() as _;

#[derive(Debug)]
#[repr(C)]
struct EnarxInterruptStackFrame {
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    frame: InterruptStackFrame,
}

#[derive(Debug)]
#[repr(C)]
struct EnarxInterruptStackFrameWithArg {
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    error_code: u64,
    frame: InterruptStackFrame,
}

/// A handler function for an interrupt or an exception without error code.
#[allow(dead_code)]
type HandlerFunc = extern "sysv64" fn(&mut EnarxInterruptStackFrame);

/// A handler function for an exception that pushes an error code.
#[allow(dead_code)]
type HandlerFuncWithErrCode =
    extern "sysv64" fn(&mut EnarxInterruptStackFrameWithArg, error_code: u64);

/// A page fault handler function that pushes a page fault error code.
#[allow(dead_code)]
type PageFaultHandlerFunc =
    extern "sysv64" fn(&mut EnarxInterruptStackFrameWithArg, error_code: PageFaultErrorCode);

/// A handler function that must not return, e.g. for a machine check exception.
#[allow(dead_code)]
type DivergingHandlerFunc = extern "sysv64" fn(&mut EnarxInterruptStackFrame) -> !;

/// A handler function with an error code that must not return, e.g. for a double fault exception.
#[allow(dead_code)]
type DivergingHandlerFuncWithErrCode =
    extern "sysv64" fn(&mut EnarxInterruptStackFrameWithArg, error_code: u64) -> !;

/// name - interrupt func name
/// number - interrupt number
/// callout - call out to extern "sysv64" function
/// has_error - has error parameter
macro_rules! declare_interrupt {
    ($name:ident : HandlerFunc => $callout:ident) => {
        declare_interrupt!($name : HandlerFunc : 0 => $callout);
    };

    ($name:ident : HandlerFuncWithErrCode => $callout:ident) => {
        declare_interrupt!($name : HandlerFuncWithErrCode : 8 => $callout);
    };

    ($name:ident : PageFaultHandlerFunc => $callout:ident) => {
        declare_interrupt!($name : PageFaultHandlerFunc : 8 => $callout);
    };

    ($name:ident : DivergingHandlerFunc => $callout:ident) => {
        declare_interrupt!($name : DivergingHandlerFunc : 0 => $callout);
    };

    ($name:ident : DivergingHandlerFuncWithErrCode => $callout:ident) => {
        declare_interrupt!($name : DivergingHandlerFuncWithErrCode : 8 => $callout);
    };

    ($name:ident : $type:ty : $skip:expr => $callout:ident) => {
        #[naked]
        #[doc = "interrupt service routine"]
        pub unsafe extern "sysv64" fn $name() -> ! {
            const _TYPE_CHECK: $type = $callout;

            asm!("
            push   rdi
            push   rsi
            push   rdx
            push   rcx
            push   rax
            push   r8
            push   r9
            push   r10
            push   r11
            push   rbx
            push   rbp

            // save stack frame
            mov    rbx, rsp
            mov    rsi, QWORD PTR [rsp+11*8]

            // rsp is first argument
            mov    rdi, rsp

            sub   rsp, {XSAVE_STACK_OFFSET}
            // align stack
            and   rsp, (~(0x40-1))

            // xsave
            // memzero xsave array
            xor     rax, rax
        2:
            mov     QWORD PTR [rsp+rax*8], 0x0
            add     eax, 0x1
            cmp     eax, ({XSAVE_STACK_OFFSET}/8)
            jne     2b

            mov   edx, -1
            mov   eax, -1
            xsave  [rsp]

            // SYSV:    rdi, rsi, rdx, rcx, r8, r9
            call  {CALLOUT}

            // xrstor
            mov   edx, -1
            mov   eax, -1
            xrstor [rsp]

            // restore stack frame
            mov    rsp, rbx

            pop    rbp
            pop    rbx
            pop    r11
            pop    r10
            pop    r9
            pop    r8
            pop    rax
            pop    rcx
            pop    rdx
            pop    rsi
            pop    rdi

            // skip error_code
            add    rsp, {SKIP}

            iretq
            ",
            SKIP = const ($skip),
            // add 64 for alignment
            XSAVE_STACK_OFFSET = const (XSAVE_AREA_SIZE + 64),
            CALLOUT = sym $callout,
            options(noreturn)
            )
        }
    };
}

declare_interrupt!(isr_0: HandlerFunc => divide_error_handler);
declare_interrupt!(isr_1: HandlerFunc => debug_handler);
declare_interrupt!(isr_2: HandlerFunc => non_maskable_interrupt_handler);
declare_interrupt!(isr_3: HandlerFunc => breakpoint_handler);
declare_interrupt!(isr_4: HandlerFunc => overflow_handler);
declare_interrupt!(isr_5: HandlerFunc => bound_range_exceeded_handler);
declare_interrupt!(isr_6: HandlerFunc => invalid_opcode_handler);
declare_interrupt!(isr_7: HandlerFunc => device_not_available_handler);
declare_interrupt!(isr_8: DivergingHandlerFuncWithErrCode => double_fault_handler);
declare_interrupt!(isr_10: HandlerFuncWithErrCode => invalid_tss_handler);
declare_interrupt!(isr_11: HandlerFuncWithErrCode => segment_not_present_handler);
declare_interrupt!(isr_12: HandlerFuncWithErrCode => stack_segment_fault);
declare_interrupt!(isr_13: HandlerFuncWithErrCode => general_protection_fault);
declare_interrupt!(isr_14: PageFaultHandlerFunc => page_fault_handler);
declare_interrupt!(isr_16: HandlerFunc => x87_floating_point_handler);
declare_interrupt!(isr_17: HandlerFuncWithErrCode => alignment_check_handler);
declare_interrupt!(isr_18: DivergingHandlerFunc => machine_check_handler);
declare_interrupt!(isr_19: HandlerFunc => simd_floating_point_handler);
declare_interrupt!(isr_20: HandlerFunc => virtualization_handler);
declare_interrupt!(isr_29: HandlerFuncWithErrCode => vmm_communication_exception_handler);
declare_interrupt!(isr_30: HandlerFuncWithErrCode => security_exception_handler);

/// The global IDT
pub static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    unsafe {
        idt.divide_error.set_handler_fn(isr_0).set_stack_index(6);
        idt.debug.set_handler_fn(isr_1).set_stack_index(1);
        idt.non_maskable_interrupt
            .set_handler_fn(isr_2)
            .set_stack_index(2);
        idt.breakpoint.set_handler_fn(isr_3).set_stack_index(1);
        idt.overflow.set_handler_fn(isr_4).set_stack_index(6);
        idt.bound_range_exceeded
            .set_handler_fn(isr_5)
            .set_stack_index(6);

        idt.invalid_opcode.set_handler_fn(isr_6).set_stack_index(5);

        idt.device_not_available
            .set_handler_fn(isr_7)
            .set_stack_index(5);

        idt.double_fault.set_handler_fn(isr_8).set_stack_index(0);

        idt.invalid_tss.set_handler_fn(isr_10).set_stack_index(6);
        idt.segment_not_present
            .set_handler_fn(isr_11)
            .set_stack_index(6);
        idt.stack_segment_fault
            .set_handler_fn(isr_12)
            .set_stack_index(6);

        idt.general_protection_fault
            .set_handler_fn(isr_13)
            .set_stack_index(6);

        idt.page_fault.set_handler_fn(isr_14).set_stack_index(6);
        idt.x87_floating_point
            .set_handler_fn(isr_16)
            .set_stack_index(6);
        idt.alignment_check
            .set_handler_fn(isr_17)
            .set_stack_index(6);
        idt.machine_check.set_handler_fn(isr_18).set_stack_index(0);
        idt.simd_floating_point
            .set_handler_fn(isr_19)
            .set_stack_index(6);
        idt.virtualization.set_handler_fn(isr_20).set_stack_index(6);
        idt.vmm_communication_exception
            .set_handler_fn(isr_29)
            .set_stack_index(6);
        idt.security_exception
            .set_handler_fn(isr_30)
            .set_stack_index(6);
    }
    idt
});

/// Initialize the IDT
pub fn init() {
    #[cfg(debug_assertions)]
    eprintln!("interrupts::init");
    IDT.load();
}

extern "sysv64" fn stack_segment_fault(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: u64,
) {
    eprintln!("stack_segment_fault {}", error_code);
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn general_protection_fault(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: u64,
) {
    eprintln!("general_protection_fault {:#b}", error_code);
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn segment_not_present_handler(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: u64,
) {
    eprintln!("segment_not_present_handler {}", error_code);
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn invalid_opcode_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("invalid_opcode_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn divide_error_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("divide_error_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn debug_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("debug_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn overflow_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("overflow_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn bound_range_exceeded_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("bound_range_exceeded_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn device_not_available_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("device_not_available_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn x87_floating_point_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("x87_floating_point_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn alignment_check_handler(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: u64,
) {
    eprintln!("alignment_check_handler");
    eprintln!("Error Code: {:?}", error_code);
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn machine_check_handler(stack_frame: &mut EnarxInterruptStackFrame) -> ! {
    eprintln!("machine_check_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn simd_floating_point_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("simd_floating_point_handler");
    eprintln!("{:#?}", stack_frame);

    let mxcsr: u32 = 0;
    unsafe {
        asm!("stmxcsr [{}]",
                in(reg) &mxcsr,
                options(nostack),
        );
    }

    eprintln!("MXCSR: {:#b}", mxcsr);

    let mut addr = stack_frame.frame.instruction_pointer;

    let payload_virt = *PAYLOAD_VIRT_ADDR.read();

    if addr.as_u64() < SHIM_VIRT_OFFSET && addr > payload_virt {
        addr -= payload_virt.as_u64();
        eprintln!("TRACE:\nP 0x{:>016x}", addr.as_u64());
    } else {
        eprintln!("TRACE:\nS 0x{:>016x}", addr.as_u64());
    };

    print_stack_trace();
    shim_exit(255);
}

extern "sysv64" fn virtualization_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("virtualization_handler");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn security_exception_handler(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: u64,
) {
    eprintln!("security_exception_handler");
    eprintln!("Error Code: {:?}", error_code);
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn vmm_communication_exception_handler(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: u64,
) {
    // AMD Progammer's Manual Vol. 2 Appendix C - SVM Intercept Exit Codes
    match error_code {
        0x72 => {
            // VMEXIT_CPUID

            let cpuid_res = cpuid_count(stack_frame.rax as _, stack_frame.rcx as _);

            stack_frame.rax = cpuid_res.eax as u64;
            stack_frame.rbx = cpuid_res.ebx as u64;
            stack_frame.rcx = cpuid_res.ecx as u64;
            stack_frame.rdx = cpuid_res.edx as u64;

            // advance RIP by length of cpuid instruction
            unsafe {
                let mut frame = stack_frame.frame.as_mut();
                frame.update(|frame| frame.instruction_pointer += 2u64)
            };
        }
        _ => panic!("Unhandled #VC: {:x?}", error_code),
    }
}

extern "sysv64" fn invalid_tss_handler(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: u64,
) {
    eprintln!("invalid_tss_handler {}", error_code);
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn breakpoint_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("EXCEPTION: BREAKPOINT");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}

extern "sysv64" fn non_maskable_interrupt_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("EXCEPTION: NMI");
    eprintln!("{:#?}", stack_frame);
}

extern "sysv64" fn page_fault_handler(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    eprintln!("EXCEPTION: PAGE FAULT");

    eprintln!("Accessed Address: {:?}", Cr2::read());
    eprintln!("Error Code: {:?}", error_code);
    eprintln!("{:x?}", stack_frame);

    let mut addr = stack_frame.frame.instruction_pointer;

    let payload_virt = *PAYLOAD_VIRT_ADDR.read();

    if addr.as_u64() < SHIM_VIRT_OFFSET && addr > payload_virt {
        addr -= payload_virt.as_u64();
    };

    eprintln!("RIP: {:?}", addr);

    print_stack_trace();

    shim_exit(255)
}

extern "sysv64" fn double_fault_handler(
    stack_frame: &mut EnarxInterruptStackFrameWithArg,
    _error_code: u64, // Always 0
) -> ! {
    eprintln!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
    shim_exit(255);
}

/*
fn unknown_interrupt_handler(stack_frame: &mut EnarxInterruptStackFrame) {
    eprintln!("EXCEPTION: unknown interrupt");
    eprintln!("{:#?}", stack_frame);
    shim_exit(255);
}
*/
