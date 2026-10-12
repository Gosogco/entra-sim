//! A record of everything the simulator does, kept as one JSON object per line in a file.
//!
//! The file is the only state the simulator keeps across a restart, so a container can be
//! stopped and started again without losing the history of what its clients did. Nothing bounds
//! it: a reset leaves it alone, and the only way to empty it is to delete the file.
//!
//! An entry's sequence number is its line index. It is not written into the line; opening the
//! file counts the lines, so the numbering continues where the last run stopped.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result};
use serde_json::Value;

pub const FILE_NAME: &str = "entra-sim.jsonl";

/// Cheap to clone; every clone appends to the same file.
#[derive(Clone)]
pub struct Log(Arc<Mutex<Inner>>);

struct Inner {
    file: File,
    /// Byte offset of the start of each line.
    offsets: Vec<u64>,
    len: u64,
}

/// Some entries, newest first, each with its `seq` added.
pub struct Page {
    pub total: u64,
    pub entries: Vec<Value>,
}

impl Log {
    /// Open the log in `dir`, creating both if needed.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;

        let mut offsets = Vec::new();
        let mut len = 0;
        let mut reader = BufReader::new(&file);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = reader
                .read_until(b'\n', &mut line)
                .with_context(|| format!("reading {}", path.display()))?;
            // A line without its newline is one a crash interrupted. It cannot be parsed, so it
            // is cut off rather than left to run into the next entry.
            if read == 0 || line.last() != Some(&b'\n') {
                break;
            }
            offsets.push(len);
            len += read as u64;
        }
        file.set_len(len)
            .with_context(|| format!("truncating {}", path.display()))?;

        Ok(Self(Arc::new(Mutex::new(Inner { file, offsets, len }))))
    }

    pub fn append(&self, entry: &Value) -> io::Result<()> {
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');

        let mut inner = self.lock();
        // One write, so a concurrent reader never sees half a line counted as a whole one.
        inner.file.write_all(&line)?;
        let start = inner.len;
        inner.offsets.push(start);
        inner.len += line.len() as u64;
        Ok(())
    }

    /// Up to `limit` entries, newest first.
    ///
    /// With `after`, the entries are the oldest ones that follow it, so a reader polling for new
    /// entries never skips any; it catches up over successive calls. Otherwise they are the
    /// newest ones before `before`, or the newest of all.
    pub fn page(&self, before: Option<u64>, after: Option<u64>, limit: usize) -> io::Result<Page> {
        let mut inner = self.lock();
        let total = inner.offsets.len();
        let end = before.map_or(total, |before| (before as usize).min(total));
        let (start, end) = match after {
            Some(after) => {
                let start = (after as usize).saturating_add(1).min(end);
                (start, end.min(start.saturating_add(limit)))
            }
            None => (end.saturating_sub(limit), end),
        };

        let mut entries = Vec::with_capacity(end - start);
        if start < end {
            let from = inner.offsets[start];
            let to = inner.offsets.get(end).copied().unwrap_or(inner.len);
            let mut bytes = vec![0; (to - from) as usize];
            inner.file.seek(SeekFrom::Start(from))?;
            inner.file.read_exact(&mut bytes)?;

            for (seq, line) in (start..end).zip(bytes.split(|b| *b == b'\n')) {
                let mut entry: Value = serde_json::from_slice(line)?;
                if let Value::Object(fields) = &mut entry {
                    fields.insert("seq".into(), seq.into());
                }
                entries.push(entry);
            }
            entries.reverse();
        }

        Ok(Page {
            total: total as u64,
            entries,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic mid-append leaves at worst a torn last line, which the next open cuts off, so
        // the log stays usable.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("entra-sim-log-{}", uuid::Uuid::new_v4())))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn seqs(page: &Page) -> Vec<u64> {
        page.entries
            .iter()
            .map(|entry| entry["seq"].as_u64().unwrap())
            .collect()
    }

    fn log_with(dir: &TempDir, count: u64) -> Log {
        let log = Log::open(&dir.0).unwrap();
        for n in 0..count {
            log.append(&json!({ "n": n })).unwrap();
        }
        log
    }

    #[test]
    fn appended_entries_come_back_newest_first_with_their_seq() {
        let dir = TempDir::new();
        let log = log_with(&dir, 3);

        let page = log.page(None, None, 10).unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(seqs(&page), [2, 1, 0]);
        assert_eq!(page.entries[0], json!({ "n": 2, "seq": 2 }));
    }

    #[test]
    fn an_empty_log_has_no_entries() {
        let dir = TempDir::new();
        let log = Log::open(&dir.0).unwrap();
        let page = log.page(None, None, 10).unwrap();
        assert_eq!(page.total, 0);
        assert!(page.entries.is_empty());
    }

    #[test]
    fn before_pages_backwards_from_the_newest() {
        let dir = TempDir::new();
        let log = log_with(&dir, 10);

        assert_eq!(seqs(&log.page(None, None, 3).unwrap()), [9, 8, 7]);
        assert_eq!(seqs(&log.page(Some(7), None, 3).unwrap()), [6, 5, 4]);
        assert_eq!(seqs(&log.page(Some(2), None, 3).unwrap()), [1, 0]);
        assert!(log.page(Some(0), None, 3).unwrap().entries.is_empty());
        assert_eq!(seqs(&log.page(Some(99), None, 2).unwrap()), [9, 8]);
    }

    #[test]
    fn after_returns_the_oldest_entries_that_follow_it() {
        let dir = TempDir::new();
        let log = log_with(&dir, 10);

        assert_eq!(seqs(&log.page(None, Some(2), 3).unwrap()), [5, 4, 3]);
        assert_eq!(seqs(&log.page(None, Some(7), 3).unwrap()), [9, 8]);
        assert!(log.page(None, Some(9), 3).unwrap().entries.is_empty());
        assert!(log.page(None, Some(99), 3).unwrap().entries.is_empty());
        assert_eq!(seqs(&log.page(Some(5), Some(2), 10).unwrap()), [4, 3]);
    }

    #[test]
    fn reopening_continues_the_numbering() {
        let dir = TempDir::new();
        drop(log_with(&dir, 2));

        let log = Log::open(&dir.0).unwrap();
        log.append(&json!({ "n": "after restart" })).unwrap();
        let page = log.page(None, None, 10).unwrap();
        assert_eq!(seqs(&page), [2, 1, 0]);
        assert_eq!(page.entries[0]["n"], "after restart");
    }

    #[test]
    fn a_torn_last_line_is_cut_off() {
        let dir = TempDir::new();
        drop(log_with(&dir, 2));
        let mut file = OpenOptions::new()
            .append(true)
            .open(dir.0.join(FILE_NAME))
            .unwrap();
        file.write_all(b"{\"n\":").unwrap();
        drop(file);

        let log = Log::open(&dir.0).unwrap();
        log.append(&json!({ "n": 2 })).unwrap();
        let page = log.page(None, None, 10).unwrap();
        assert_eq!(seqs(&page), [2, 1, 0]);
        assert_eq!(page.entries[0]["n"], 2);
    }
}
