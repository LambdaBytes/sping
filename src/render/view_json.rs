//! NDJSON view: one JSON object per probe, one per line. The output schema
//! is frozen — see `JSON_CONTRACT.md` before changing any field. No raw
//! mode, so output is safe to pipe.

use std::io::{self, Write};

use crate::probe::types::ProbeSnapshot;

/// JSON view state; deduplicates on `seq` so each probe prints once.
pub struct JsonView {
    last_seq: u64,
}

impl JsonView {
    pub fn new() -> Self {
        Self { last_seq: 0 }
    }

    /// Print one JSON line if `snap.seq` advanced; otherwise a no-op.
    /// Serialization failures warn on stderr without returning an error.
    pub fn draw(&mut self, w: &mut impl Write, snap: &ProbeSnapshot) -> io::Result<()> {
        if snap.seq == 0 || snap.seq <= self.last_seq {
            return Ok(());
        }
        self.last_seq = snap.seq;

        // Never emit a bogus "{}" line: skip and warn if serialization fails.
        match serde_json::to_string(snap) {
            Ok(json) => {
                writeln!(w, "{json}")?;
                w.flush()?;
            }
            Err(e) => {
                eprintln!("warning: cannot serialize snapshot: {e}");
            }
        }
        Ok(())
    }
}
