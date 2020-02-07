// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// A yet-to-be-ran test
pub struct Test {
    /// A good description of what the test is for
    pub name: &'static str,

    /// A function or closure that will perform a single test. This returns
    /// a tuple consisting of a Result that indicates if the test passed or
    /// failed, as well as an optional string that can convey more information
    /// in the test's output.
    pub func: Box<dyn Fn() -> (Result<(), ()>, Option<String>)>,

    /// Any dependent tests that may be ran if this parent test passes
    /// (example: it doesn't make sense to run any AMD-specific tests if
    /// running on an Intel chip)
    pub dependents: Vec<Test>,
}

impl Test {
    /// Consumes the `Test`, executes the test function and captures its
    /// result. If this test passes, it will recursively kick off and subsequently
    /// capture any of the child tests (and their child tests (and their child tests))
    pub fn run(self) -> CompletedTest {
        let (res, optional_info) = (self.func)();

        let deps = match res {
            Ok(_) => Some(self.dependents.into_iter().map(|d| d.run()).collect()),
            Err(_) => None,
        };

        CompletedTest {
            name: self.name,
            info: optional_info,
            dependents: deps,
        }
    }
}

/// A test which has been ran and its success or failure captured (as well as its
/// child tests, if applicable)
pub struct CompletedTest {
    /// The original `Test` description
    name: &'static str,

    pub info: Option<String>,

    /// If the test did not pass, then `dependents` will be `None`. Otherwise,
    /// `dependents` will be `Some` and will contain a `Vec` of the child
    /// `CompletedTest`s.
    pub dependents: Option<Vec<CompletedTest>>,
}

impl CompletedTest {
    pub fn passed(&self) -> bool {
        self.dependents.is_some()
    }
}

impl fmt::Display for CompletedTest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaves_of_a_failed_test_are_not_ran() {
        let test = Test {
            name: "Doomed to fail",
            func: Box::new(|| (Err(()), None)),
            dependents: vec![Test {
                name: "Shouldn't reach here",
                func: Box::new(|| (Ok(()), None)),
                dependents: vec![],
            }],
        };

        let completed = test.run();
        assert!(completed.dependents.is_none());
    }

    #[test]
    fn test_leaves_of_a_passing_test_are_ran() {
        let test = Test {
            name: "Vacuously true",
            func: Box::new(|| (Ok(()), None)),
            dependents: vec![Test {
                name: "Also true",
                func: Box::new(|| (Ok(()), None)),
                dependents: vec![],
            }],
        };

        let completed = test.run();
        assert!(completed.dependents.is_some());
    }
}
