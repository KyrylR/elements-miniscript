// SPDX-License-Identifier: CC0-1.0
use std::fmt;
use std::str::FromStr;

use simplicity::Cmr;

use crate::Error;

/// A Simplicity program commitment used as a Taproot leaf.
///
/// Displayed as `sim{asm(CMR)}`. The CMR does not expose the program, its keys or
/// its spending conditions. Callers must retain the program separately.
/// Constructing or parsing a leaf does not validate the program or its witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct SimplicityLeaf(Cmr);

impl SimplicityLeaf {
    /// Construct a commitment-only leaf without validating a program.
    pub fn from_cmr(cmr: Cmr) -> Self {
        Self(cmr)
    }

    /// Return the program commitment.
    pub fn cmr(&self) -> Cmr {
        self.0
    }
}

impl fmt::Display for SimplicityLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sim{{asm({})}}", self.0)
    }
}

impl FromStr for SimplicityLeaf {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cmr = s
            .strip_prefix("sim{asm(")
            .and_then(|s| s.strip_suffix(")}"))
            .ok_or_else(|| Error::Unexpected("expected sim{asm(CMR)}".into()))?;
        Cmr::from_str(cmr)
            .map(Self::from_cmr)
            .map_err(|e| Error::Unexpected(e.to_string()))
    }
}
