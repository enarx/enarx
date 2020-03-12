// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;

pub trait Executor {
    fn exec(&self, indent: usize, success: bool);
}

pub struct Test<T, U: TryFrom<T>> {
    pub name: &'static str,
    pub data: Box<dyn super::data::Data<Type = T>>,
    pub sink: Box<dyn super::sink::Sink<Type = U>>,
    pub next: Vec<Box<dyn Executor>>,
}

impl<T, U: TryFrom<T>> Test<T, U> {
    fn dump(&self, indent: usize, data: Option<U>) {
        use colorful::*;

        let prefix = if data.is_some() {
            "✔".green()
        } else {
            "✗".red()
        };

        let info = data.and_then(|d| self.sink.info(&d));

        println!(
            "{:>okay$} {:name$} {:24} {}",
            prefix,
            self.name,
            self.data,
            info.unwrap_or_else(String::new),
            okay = 1 + indent,
            name = 24 - indent
        );
    }
}

impl<T, U: TryFrom<T>> Executor for Test<T, U> {
    fn exec(&self, indent: usize, success: bool) {
        let mut data = None;

        if success {
            if let Some(t) = self.data.data() {
                if let Ok(u) = U::try_from(t) {
                    if self.sink.test(&u) {
                        data = Some(u);
                    }
                }
            }
        };

        self.dump(indent, data);

        for next in self.next.iter() {
            next.exec(indent + 2, success);
        }
    }
}
