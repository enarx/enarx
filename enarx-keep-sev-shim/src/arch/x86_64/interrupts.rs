// SPDX-License-Identifier: Apache-2.0

use super::gdt;
use super::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use crate::{eprintln, exit_hypervisor, hlt_loop, HyperVisorExitCode};

extern "C" {
    pub fn _isr_0(vars: &mut InterruptStackFrame);
    pub fn _isr_1(vars: &mut InterruptStackFrame);
    pub fn _isr_2(vars: &mut InterruptStackFrame);
    pub fn _isr_3(vars: &mut InterruptStackFrame);
    pub fn _isr_4(vars: &mut InterruptStackFrame);
    pub fn _isr_5(vars: &mut InterruptStackFrame);
    pub fn _isr_6(vars: &mut InterruptStackFrame);
    pub fn _isr_7(vars: &mut InterruptStackFrame);
    pub fn _isr_8(vars: &mut InterruptStackFrame, error_code: u64) -> !;
    pub fn _isr_10(vars: &mut InterruptStackFrame, error_code: u64);
    pub fn _isr_11(vars: &mut InterruptStackFrame, error_code: u64);
    pub fn _isr_12(vars: &mut InterruptStackFrame, error_code: u64);
    pub fn _isr_13(vars: &mut InterruptStackFrame, error_code: u64);
    pub fn _isr_14(vars: &mut InterruptStackFrame, error_code: PageFaultErrorCode);
    pub fn _isr_16(vars: &mut InterruptStackFrame);
    pub fn _isr_17(vars: &mut InterruptStackFrame, error_code: u64);
    pub fn _isr_18(vars: &mut InterruptStackFrame) -> !;
    pub fn _isr_19(vars: &mut InterruptStackFrame);
    pub fn _isr_20(vars: &mut InterruptStackFrame);
    pub fn _isr_30(vars: &mut InterruptStackFrame, error_code: u64);
/*
    pub fn _isr_32(vars: &mut InterruptStackFrame);
    pub fn _isr_33(vars: &mut InterruptStackFrame);
    pub fn _isr_100(vars: &mut InterruptStackFrame);
    pub fn _isr_101(vars: &mut InterruptStackFrame);
    pub fn _isr_102(vars: &mut InterruptStackFrame);
*/
}

pub static mut IDT: Option<InterruptDescriptorTable> = None;

#[no_mangle]
pub extern "C" fn run_interrupt_fn(vars: &mut InterruptStackFrame, error_code: u64, irq: u64) {
    println!("IRQ starts {}", irq);
    match irq {
        0 => divide_error_handler(vars),
        1 => debug_handler(vars),
        2 => non_maskable_interrupt_handler(vars),
        3 => breakpoint_handler(vars),
        4 => overflow_handler(vars),
        5 => bound_range_exceeded_handler(vars),
        6 => invalid_opcode_handler(vars),
        7 => device_not_available_handler(vars),
        8 => double_fault_handler(vars, error_code),
        9 => {}
        10 => invalid_tss_handler(vars, error_code),
        11 => segment_not_present_handler(vars, error_code),
        12 => stack_segment_fault(vars, error_code),
        13 => general_protection_fault(vars, error_code),
        14 => page_fault_handler(vars, unsafe {
            PageFaultErrorCode::from_bits_unchecked(error_code)
        }),
        15 => {}
        16 => x87_floating_point_handler(vars),
        17 => alignment_check_handler(vars, error_code),
        18 => machine_check_handler(vars),
        19 => simd_floating_point_handler(vars),
        20 => virtualization_handler(vars),
        21..=29 => {}
        30 => security_exception_handler(vars, error_code),
        31 => {}
        _ => panic!("Unknown int {}", irq),
    }

    // println!("IRQend {}", irq);
}

pub fn init() {
    #[cfg(debug_assertions)]
    eprintln!("interrupts::init");
    unsafe {
        IDT.replace({
            let mut idt = InterruptDescriptorTable::new();
            idt.divide_error.set_handler_fn(_isr_0).set_stack_index(6);
            idt.debug.set_handler_fn(_isr_1).set_stack_index(1);
            idt.non_maskable_interrupt
                .set_handler_fn(_isr_2)
                .set_stack_index(2);
            idt.breakpoint.set_handler_fn(_isr_3).set_stack_index(1);
            idt.overflow.set_handler_fn(_isr_4).set_stack_index(6);
            idt.bound_range_exceeded
                .set_handler_fn(_isr_5)
                .set_stack_index(6);
            idt.invalid_opcode.set_handler_fn(_isr_6).set_stack_index(5);
            idt.device_not_available
                .set_handler_fn(_isr_7)
                .set_stack_index(5);
            idt.double_fault
                .set_handler_fn(_isr_8)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
            idt.invalid_tss.set_handler_fn(_isr_10).set_stack_index(6);
            idt.segment_not_present
                .set_handler_fn(_isr_11)
                .set_stack_index(6);
            idt.stack_segment_fault
                .set_handler_fn(_isr_12)
                .set_stack_index(6);
            idt.general_protection_fault
                .set_handler_fn(_isr_13)
                .set_stack_index(6);
            idt.page_fault.set_handler_fn(_isr_14).set_stack_index(6);
            idt.x87_floating_point
                .set_handler_fn(_isr_16)
                .set_stack_index(6);
            idt.alignment_check
                .set_handler_fn(_isr_17)
                .set_stack_index(6);
            idt.machine_check.set_handler_fn(_isr_18).set_stack_index(0);
            idt.simd_floating_point
                .set_handler_fn(_isr_19)
                .set_stack_index(6);
            idt.virtualization
                .set_handler_fn(_isr_20)
                .set_stack_index(6);
            idt.security_exception
                .set_handler_fn(_isr_30)
                .set_stack_index(6);

            #[cfg(feature = "timer")]
            crate::arch::x86_64::timer::timer_set_idt(core::mem::transmute(&mut idt));
            /*
            for i in 32..256 {
                idt[i].set_handler_fn(unknown_interrupt_handler);
            }
            */
            idt
        });
        IDT.as_ref().unwrap().load();
    }

    #[cfg(feature = "timer")]
    super::timer::timer_init();

    #[cfg(feature = "timer")]
    x86_64::instructions::interrupts::enable();
}

fn stack_segment_fault(stack_frame: &mut InterruptStackFrame, error_code: u64) {
    eprintln!("stack_segment_fault {}", error_code);
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn general_protection_fault(stack_frame: &mut InterruptStackFrame, error_code: u64) {
    eprintln!("general_protection_fault {:#b}", error_code);
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn segment_not_present_handler(stack_frame: &mut InterruptStackFrame, error_code: u64) {
    eprintln!("segment_not_present_handler {}", error_code);
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn invalid_opcode_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("invalid_opcode_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn divide_error_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("divide_error_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn debug_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("debug_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn overflow_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("overflow_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn bound_range_exceeded_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("bound_range_exceeded_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn device_not_available_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("device_not_available_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn x87_floating_point_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("x87_floating_point_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn alignment_check_handler(stack_frame: &mut InterruptStackFrame, error_code: u64) {
    eprintln!("alignment_check_handler");
    eprintln!("Error Code: {:?}", error_code);
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn machine_check_handler(stack_frame: &mut InterruptStackFrame) -> ! {
    eprintln!("machine_check_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn simd_floating_point_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("simd_floating_point_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn virtualization_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("virtualization_handler");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn security_exception_handler(stack_frame: &mut InterruptStackFrame, error_code: u64) {
    eprintln!("security_exception_handler");
    eprintln!("Error Code: {:?}", error_code);
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn invalid_tss_handler(stack_frame: &mut InterruptStackFrame, error_code: u64) {
    eprintln!("invalid_tss_handler {}", error_code);
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn breakpoint_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("EXCEPTION: BREAKPOINT");
    eprintln!("{:#?}", stack_frame);
}

fn non_maskable_interrupt_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("EXCEPTION: NMI");
    eprintln!("{:#?}", stack_frame);
}

fn page_fault_handler(stack_frame: &mut InterruptStackFrame, error_code: PageFaultErrorCode) {
    use x86_64::registers::control::Cr2;

    eprintln!("EXCEPTION: PAGE FAULT");
    eprintln!("Accessed Address: {:?}", Cr2::read());
    eprintln!("Error Code: {:?}", error_code);
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

fn double_fault_handler(
    stack_frame: &mut InterruptStackFrame,
    _error_code: u64, // Always 0
) -> ! {
    eprintln!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}
/*
fn unknown_interrupt_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("EXCEPTION: unknown interrupt");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}
*/

#[cfg(all(test, feature = "nightly"))]
#[test_case]
fn test_breakpoint_exception() {
    use crate::{print, println};
    print!("test_breakpoint_exception...");
    // invoke a breakpoint exception
    x86_64::instructions::interrupts::int3();
    println!("[ok]");
}
