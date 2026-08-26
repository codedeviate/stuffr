//! Central resource governance. Nothing in the codebase spawns a thread
//! outside the governor.

pub mod budget;

pub use budget::{BudgetInputs, DEFAULT_CAP, detect_cpu_budget, resolve_workers};
