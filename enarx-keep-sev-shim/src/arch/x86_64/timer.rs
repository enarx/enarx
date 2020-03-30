// SPDX-License-Identifier: Apache-2.0

use lazy_static::lazy_static;
use pic8259_simple::ChainedPics;
use spin::Mutex;

use crate::{exit_hypervisor, hlt_loop, HyperVisorExitCode};
use x2apic::lapic::{LocalApic, LocalApicBuilder, TimerDivide, TimerMode};
use x86_64::instructions::port::Port;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
    LapicTimer = 100,
    Error,
    Spurious,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

pub static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

lazy_static! {
    pub static ref LAPIC: Mutex<Option<LocalApic>> = {
        let lapic = LocalApicBuilder::new()
            .timer_vector(InterruptIndex::LapicTimer.as_usize())
            .timer_initial(0x100_0000)
            .timer_divide(TimerDivide::Div256)
            .timer_mode(TimerMode::Periodic)
            .error_vector(InterruptIndex::Error.as_usize())
            .spurious_vector(InterruptIndex::Spurious.as_usize())
            .build();

        Mutex::new(lapic.ok())
    };
}

pub fn timer_init() {
    if let Some(l) = LAPIC.lock().as_mut() {
        unsafe {
            l.enable();
            l.enable_timer();
        }
    }
    unsafe {
        PICS.lock().initialize();
    };

    let mut cp = Port::new(0x43);
    unsafe {
        cp.write(0b00110100_u8);
    }
    let mut p = Port::new(0x40);
    unsafe {
        p.write(0xFF_u8);
        p.write(0xFF_u8);
    }
}

pub fn timer_set_idt(idt: &mut InterruptDescriptorTable) {
    eprintln!("timer_set_idt");
    idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);
    idt[InterruptIndex::LapicTimer.as_usize()].set_handler_fn(lapic_timer_interrupt_handler);
    idt[InterruptIndex::Error.as_usize()].set_handler_fn(error_interrupt_handler);
    idt[InterruptIndex::Spurious.as_usize()].set_handler_fn(spurious_interrupt_handler);
    idt[InterruptIndex::Keyboard.as_usize()].set_handler_fn(keyboard_interrupt_handler);
}

extern "x86-interrupt" fn spurious_interrupt_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("EXCEPTION: spurious interrupt");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

extern "x86-interrupt" fn error_interrupt_handler(stack_frame: &mut InterruptStackFrame) {
    eprintln!("EXCEPTION: error interrupt");
    eprintln!("{:#?}", stack_frame);
    exit_hypervisor(HyperVisorExitCode::Failed);
    hlt_loop();
}

extern "x86-interrupt" fn lapic_timer_interrupt_handler(_stack_frame: &mut InterruptStackFrame) {
    #[cfg(debug_assertions)]
    eprintln!("*");
    unsafe {
        if let Some(l) = LAPIC.lock().as_mut() {
            l.end_of_interrupt();
        }
    }
}

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: &mut InterruptStackFrame) {
    #[cfg(debug_assertions)]
    eprintln!(".");
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: &mut InterruptStackFrame) {
    //use pc_keyboard::{layouts, DecodedKey, Keyboard, ScancodeSet1};
    let mut port = Port::new(0x60);

    let scancode: u8 = unsafe { port.read() };

    eprintln!("Keyboard scancode {}", scancode);
    /*
        if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
            if let Some(key) = keyboard.process_keyevent(key_event) {
                match key {
                    DecodedKey::Unicode(character) => print!("{}", character),
                    DecodedKey::RawKey(key) => print!("{:?}", key),
                }
            }
        }
    */
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
