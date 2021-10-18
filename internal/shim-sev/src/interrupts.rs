// SPDX-License-Identifier: Apache-2.0

//! Interrupt handling

use crate::addr::SHIM_VIRT_OFFSET;
use crate::debug::print_stack_trace;
use crate::eprintln;
use crate::hostcall::shim_exit;
use crate::idt::InterruptDescriptorTable;
use crate::payload::PAYLOAD_VIRT_ADDR;
use crate::snp::cpuid_count;

use core::fmt;
use core::mem::size_of;
use core::ops::Deref;

use paste::paste;
use spinning::Lazy;
use x86_64::structures::idt::PageFaultErrorCode;
use x86_64::VirtAddr;
use xsave::XSave;

/// size of area reserved for xsave
pub const XSAVE_AREA_SIZE: u32 = size_of::<XSave>() as _;

#[repr(C)]
struct ExtendedInterruptStackFrame {
    value: ExtendedInterruptStackFrameValue,
}

impl ExtendedInterruptStackFrame {
    /// Gives mutable access to the contents of the interrupt stack frame.
    ///
    /// The `Volatile` wrapper is used because LLVM optimizations remove non-volatile
    /// modifications of the interrupt stack frame.
    ///
    /// ## Safety
    ///
    /// This function is unsafe since modifying the content of the interrupt stack frame
    /// can easily lead to undefined behavior. For example, by writing an invalid value to
    /// the instruction pointer field, the CPU can jump to arbitrary code at the end of the
    /// interrupt.
    ///
    /// Also, it is not fully clear yet whether modifications of the interrupt stack frame are
    /// officially supported by LLVM's x86 interrupt calling convention.
    #[inline]
    unsafe fn as_mut(&mut self) -> &mut ExtendedInterruptStackFrameValue {
        &mut self.value
    }
}

impl Deref for ExtendedInterruptStackFrame {
    type Target = ExtendedInterruptStackFrameValue;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl fmt::Debug for ExtendedInterruptStackFrame {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

#[derive(Debug)]
#[repr(C)]
struct ExtendedInterruptStackFrameValue {
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rdi: u64,
    rsi: u64,
    /// This value points to the instruction that should be executed when the interrupt
    /// handler returns. For most interrupts, this value points to the instruction immediately
    /// following the last executed instruction. However, for some exceptions (e.g., page faults),
    /// this value points to the faulting instruction, so that the instruction is restarted on
    /// return. See the documentation of the [`InterruptDescriptorTable`] fields for more details.
    instruction_pointer: VirtAddr,
    /// The code segment selector, padded with zeros.
    code_segment: u64,
    /// The flags register before the interrupt handler was invoked.
    cpu_flags: u64,
    /// The stack pointer at the time of the interrupt.
    stack_pointer: VirtAddr,
    /// The stack segment descriptor at the time of the interrupt (often zero in 64-bit mode).
    stack_segment: u64,
}

/// name - interrupt func name
/// number - interrupt number
/// callout - call out to extern "sysv64" function
/// has_error - has error parameter
macro_rules! declare_interrupt {
    (fn $name:ident ( $stack:ident : &mut ExtendedInterruptStackFrame $(,)? ) $code:block) => {
        paste! {
            extern "sysv64" fn [<__interrupt_ $name>]($stack: &mut ExtendedInterruptStackFrame) {
                $code
            }
        }
        declare_interrupt!($name => "push rsi");
    };

    (fn $name:ident ( $stack:ident : &mut ExtendedInterruptStackFrame , $error:ident : u64 $(,)? ) $code:block) => {
        paste! {
            extern "sysv64" fn [<__interrupt_ $name>]($stack: &mut ExtendedInterruptStackFrame, $error: u64) {
                $code
            }
        }
        declare_interrupt!($name => "xchg [rsp], rsi");
    };

    (fn $name:ident ( $stack:ident : &mut ExtendedInterruptStackFrame , $error:ident : PageFaultErrorCode $(,)? ) $code:block) => {
        paste! {
            extern "sysv64" fn [<__interrupt_ $name>]($stack: &mut ExtendedInterruptStackFrame, $error: PageFaultErrorCode) {
                $code
            }
        }
        declare_interrupt!($name => "xchg [rsp], rsi");
    };

    (fn $name:ident ( $stack:ident : &mut ExtendedInterruptStackFrame $(,)? ) -> ! $code:block) => {
        paste! {
            extern "sysv64" fn [<__interrupt_ $name>]($stack: &mut ExtendedInterruptStackFrame) {
                $code
            }
        }
        declare_interrupt!($name => "push rsi");
    };

    (fn $name:ident ( $stack:ident : &mut ExtendedInterruptStackFrame, $error:ident : u64 $(,)? )  -> ! $code:block) => {
        paste! {
            extern "sysv64" fn [<__interrupt_ $name>]($stack: &mut ExtendedInterruptStackFrame, $error: u64) {
                $code
            }
        }
        declare_interrupt!($name => "xchg [rsp], rsi");
    };

    ($name:ident => $push_or_exchange:literal) => {
        paste! {
            #[naked]
            unsafe extern "sysv64" fn $name() -> ! {
                asm!(
                    // either push rsi or exchange with error code
                    $push_or_exchange,
                    "push   rdi",
                    "push   rdx",
                    "push   rcx",
                    "push   rax",
                    "push   r8",
                    "push   r9",
                    "push   r10",
                    "push   r11",
                    "push   rbx",
                    "push   rbp",

                    // save stack frame
                    "mov    rbx, rsp",

                    // rsp is first argument
                    "mov    rdi, rsp",

                    "sub   rsp, {XSAVE_STACK_OFFSET}",
                    // align stack
                    "and   rsp, (~(0x40-1))",

                    // xsave
                    // memzero xsave array
                    "xor     rax, rax",
                    "2:",
                    "mov     QWORD PTR [rsp+rax*8], 0x0",
                    "add     eax, 0x1",
                    "cmp     eax, ({XSAVE_STACK_OFFSET}/8)",
                    "jne     2b",

                    "mov   edx, -1",
                    "mov   eax, -1",
                    "xsave  [rsp]",

                    // SYSV:    rdi, rsi, rdx, rcx, r8, r9
                    "call  {CALLOUT}",

                    // xrstor
                    "mov   edx, -1",
                    "mov   eax, -1",
                    "xrstor [rsp]",

                    // restore stack frame
                    "mov    rsp, rbx",

                    "pop    rbp",
                    "pop    rbx",
                    "pop    r11",
                    "pop    r10",
                    "pop    r9",
                    "pop    r8",
                    "pop    rax",
                    "pop    rcx",
                    "pop    rdx",
                    "pop    rdi",
                    "pop    rsi",

                    "iretq",

                    // add 64 for alignment
                    XSAVE_STACK_OFFSET = const (XSAVE_AREA_SIZE + 64),
                    CALLOUT = sym [<__interrupt_ $name>],

                    options(noreturn)
                )
            }
        }
    };
}

/// The global IDT
pub static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    unsafe {
        let virt = VirtAddr::new_unsafe(divide_error_handler as usize as u64);
        idt.divide_error.set_handler_addr(virt).set_stack_index(6);

        let virt = VirtAddr::new_unsafe(debug_handler as usize as u64);
        idt.debug.set_handler_addr(virt).set_stack_index(1);

        let virt = VirtAddr::new_unsafe(non_maskable_interrupt_handler as usize as u64);
        idt.non_maskable_interrupt
            .set_handler_addr(virt)
            .set_stack_index(2);

        let virt = VirtAddr::new_unsafe(breakpoint_handler as usize as u64);
        idt.breakpoint.set_handler_addr(virt).set_stack_index(1);

        let virt = VirtAddr::new_unsafe(overflow_handler as usize as u64);
        idt.overflow.set_handler_addr(virt).set_stack_index(6);

        let virt = VirtAddr::new_unsafe(bound_range_exceeded_handler as usize as u64);
        idt.bound_range_exceeded
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(invalid_opcode_handler as usize as u64);
        idt.invalid_opcode.set_handler_addr(virt).set_stack_index(5);

        let virt = VirtAddr::new_unsafe(device_not_available_handler as usize as u64);
        idt.device_not_available
            .set_handler_addr(virt)
            .set_stack_index(5);

        let virt = VirtAddr::new_unsafe(double_fault_handler as usize as u64);
        idt.double_fault.set_handler_addr(virt).set_stack_index(0);

        let virt = VirtAddr::new_unsafe(invalid_tss_handler as usize as u64);
        idt.invalid_tss.set_handler_addr(virt).set_stack_index(6);

        let virt = VirtAddr::new_unsafe(segment_not_present_handler as usize as u64);
        idt.segment_not_present
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(stack_segment_fault as usize as u64);
        idt.stack_segment_fault
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(general_protection_fault as usize as u64);
        idt.general_protection_fault
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(page_fault_handler as usize as u64);
        idt.page_fault.set_handler_addr(virt).set_stack_index(6);

        let virt = VirtAddr::new_unsafe(x87_floating_point_handler as usize as u64);
        idt.x87_floating_point
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(alignment_check_handler as usize as u64);
        idt.alignment_check
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(machine_check_handler as usize as u64);
        idt.machine_check.set_handler_addr(virt).set_stack_index(0);

        let virt = VirtAddr::new_unsafe(simd_floating_point_handler as usize as u64);
        idt.simd_floating_point
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(virtualization_handler as usize as u64);
        idt.virtualization.set_handler_addr(virt).set_stack_index(6);

        let virt = VirtAddr::new_unsafe(vmm_communication_exception_handler as usize as u64);
        idt.vmm_communication_exception
            .set_handler_addr(virt)
            .set_stack_index(6);

        let virt = VirtAddr::new_unsafe(security_exception_handler as usize as u64);
        idt.security_exception
            .set_handler_addr(virt)
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

declare_interrupt!(
    fn stack_segment_fault(stack_frame: &mut ExtendedInterruptStackFrame, error_code: u64) {
        eprintln!("stack_segment_fault {}", error_code);
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn general_protection_fault(stack_frame: &mut ExtendedInterruptStackFrame, error_code: u64) {
        eprintln!("general_protection_fault {:#b}", error_code);
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn segment_not_present_handler(stack_frame: &mut ExtendedInterruptStackFrame, error_code: u64) {
        eprintln!("segment_not_present_handler {}", error_code);
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn invalid_opcode_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("invalid_opcode_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn divide_error_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("divide_error_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn debug_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("debug_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn overflow_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("overflow_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn bound_range_exceeded_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("bound_range_exceeded_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn device_not_available_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("device_not_available_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn x87_floating_point_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("x87_floating_point_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn alignment_check_handler(stack_frame: &mut ExtendedInterruptStackFrame, error_code: u64) {
        eprintln!("alignment_check_handler");
        eprintln!("Error Code: {:?}", error_code);
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn machine_check_handler(stack_frame: &mut ExtendedInterruptStackFrame) -> ! {
        eprintln!("machine_check_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn simd_floating_point_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
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

        let mut addr = stack_frame.instruction_pointer;

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
);

declare_interrupt!(
    fn virtualization_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("virtualization_handler");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn security_exception_handler(stack_frame: &mut ExtendedInterruptStackFrame, error_code: u64) {
        eprintln!("security_exception_handler");
        eprintln!("Error Code: {:?}", error_code);
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn vmm_communication_exception_handler(
        stack_frame: &mut ExtendedInterruptStackFrame,
        error_code: u64,
    ) {
        // AMD Progammer's Manual Vol. 2 Appendix C - SVM Intercept Exit Codes
        match error_code {
            0x72 => {
                // VMEXIT_CPUID

                let cpuid_res = cpuid_count(stack_frame.rax as _, stack_frame.rcx as _);

                unsafe {
                    let stack_frame = stack_frame.as_mut();
                    stack_frame.rax = cpuid_res.eax as u64;
                    stack_frame.rbx = cpuid_res.ebx as u64;
                    stack_frame.rcx = cpuid_res.ecx as u64;
                    stack_frame.rdx = cpuid_res.edx as u64;

                    // advance RIP by length of cpuid instruction
                    stack_frame.instruction_pointer += 2u64
                }
            }
            _ => panic!("Unhandled #VC: {:x?}", error_code),
        }
    }
);

declare_interrupt!(
    fn invalid_tss_handler(stack_frame: &mut ExtendedInterruptStackFrame, error_code: u64) {
        eprintln!("invalid_tss_handler {}", error_code);
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn breakpoint_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("EXCEPTION: BREAKPOINT");
        eprintln!("{:#?}", stack_frame);
        shim_exit(255);
    }
);

declare_interrupt!(
    fn non_maskable_interrupt_handler(stack_frame: &mut ExtendedInterruptStackFrame) {
        eprintln!("EXCEPTION: NMI");
        eprintln!("{:#?}", stack_frame);
    }
);

declare_interrupt!(
    fn page_fault_handler(
        stack_frame: &mut ExtendedInterruptStackFrame,
        error_code: PageFaultErrorCode,
    ) {
        use x86_64::registers::control::Cr2;

        eprintln!("EXCEPTION: PAGE FAULT");

        eprintln!("Accessed Address: {:?}", Cr2::read());
        eprintln!("Error Code: {:?}", error_code);
        eprintln!("{:x?}", stack_frame);

        let mut addr = stack_frame.instruction_pointer;

        let payload_virt = *PAYLOAD_VIRT_ADDR.read();

        if addr.as_u64() < SHIM_VIRT_OFFSET && addr > payload_virt {
            addr -= payload_virt.as_u64();
        };

        eprintln!("RIP: {:?}", addr);

        print_stack_trace();

        shim_exit(255)
    }
);

declare_interrupt!(
    fn double_fault_handler(
        stack_frame: &mut ExtendedInterruptStackFrame,
        _error_code: u64, // Always 0
    ) -> ! {
        eprintln!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
        shim_exit(255);
    }
);
