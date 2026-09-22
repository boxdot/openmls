//! Allocation baseline for the hot paths, measured with [dhat](https://docs.rs/dhat).
//!
//! Prints allocations per operation on a 2-member group. `--save-baseline`
//! stores the numbers as JSON and `--baseline` compares a run against such a
//! file. `--save` writes one dhat JSON per operation for
//! <https://nnethercote.github.io/dh_view/dh_view.html>.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use clap::Parser;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const PAYLOAD: [u8; 100] = [0x42; 100];

/// Heap statistics of one profiled operation.
#[derive(Serialize, Deserialize)]
struct Measurement {
    provider: String,
    operation: String,
    /// Number of allocations.
    allocs: u64,
    /// Bytes allocated in total.
    bytes: u64,
    /// Peak heap size.
    peak: usize,
    /// Bytes still allocated when the operation returned.
    retained: usize,
}

/// The result of one run; the format `--save-baseline` writes and
/// `--baseline` reads.
#[derive(Serialize, Deserialize)]
struct Report {
    ciphersuite: String,
    payload_bytes: usize,
    measurements: Vec<Measurement>,
}

impl Report {
    fn find(&self, provider: &str, operation: &str) -> Option<&Measurement> {
        self.measurements
            .iter()
            .find(|m| m.provider == provider && m.operation == operation)
    }

    fn load(path: &Path) -> Report {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("failed to read baseline {}: {e}", path.display()));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to parse baseline {}: {e}", path.display()))
    }

    fn save(&self, path: &Path) {
        let json = serde_json::to_string_pretty(self).expect("failed to serialize report");
        std::fs::write(path, json)
            .unwrap_or_else(|e| panic!("failed to write baseline {}: {e}", path.display()));
    }

    /// Renders the report as a Markdown table, which also reads fine in a
    /// terminal. With a baseline, every metric gets a column with the change
    /// against it.
    fn render(&self, baseline: Option<&Report>) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Allocation baseline: 2-member group, {}, {}-byte payload",
            self.ciphersuite, self.payload_bytes
        );
        if let Some(baseline) = baseline {
            if baseline.ciphersuite != self.ciphersuite
                || baseline.payload_bytes != self.payload_bytes
            {
                let _ = writeln!(
                    out,
                    "WARNING: baseline was taken with {}, {}-byte payload",
                    baseline.ciphersuite, baseline.payload_bytes
                );
            }
        }
        let _ = writeln!(out);

        let mut table = Table::new(["provider", "operation"]);
        for metric in ["allocs", "bytes", "peak", "retained"] {
            table.header.push(metric.to_owned());
            if baseline.is_some() {
                table.header.push(format!("Δ {metric}"));
            }
        }
        for m in &self.measurements {
            let old = baseline.and_then(|b| b.find(&m.provider, &m.operation));
            let mut row = vec![m.provider.clone(), m.operation.clone()];
            let metrics = [
                (m.allocs, old.map(|o| o.allocs)),
                (m.bytes, old.map(|o| o.bytes)),
                (m.peak as u64, old.map(|o| o.peak as u64)),
                (m.retained as u64, old.map(|o| o.retained as u64)),
            ];
            for (new, old) in metrics {
                row.push(new.to_string());
                if baseline.is_some() {
                    row.push(old.map_or_else(|| "new".to_owned(), |old| delta(new, old)));
                }
            }
            table.rows.push(row);
        }
        table.render(&mut out);
        out
    }
}

/// Formats the change from `old` to `new`, e.g. `-20 (-33.9%)`.
fn delta(new: u64, old: u64) -> String {
    let diff = new as i128 - old as i128;
    if diff == 0 {
        return "0".to_owned();
    }
    if old == 0 {
        return format!("{diff:+}");
    }
    let percent = diff as f64 * 100.0 / old as f64;
    format!("{diff:+} ({percent:+.1}%)")
}

/// A Markdown table with left-aligned text columns and right-aligned numbers.
struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
    /// Number of leading columns that hold text rather than numbers.
    text_columns: usize,
}

impl Table {
    fn new<const N: usize>(text_columns: [&str; N]) -> Self {
        Self {
            header: text_columns.iter().map(|s| (*s).to_owned()).collect(),
            rows: Vec::new(),
            text_columns: N,
        }
    }

    fn render(&self, out: &mut String) {
        let widths: Vec<usize> = (0..self.header.len())
            .map(|i| {
                self.rows
                    .iter()
                    .map(|row| row[i].chars().count())
                    .chain([self.header[i].chars().count()])
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let line = |out: &mut String, cells: &[String]| {
            out.push('|');
            for (i, (cell, width)) in cells.iter().zip(&widths).enumerate() {
                let pad = width - cell.chars().count();
                if i < self.text_columns {
                    let _ = write!(out, " {cell}{} |", " ".repeat(pad));
                } else {
                    let _ = write!(out, " {}{cell} |", " ".repeat(pad));
                }
            }
            out.push('\n');
        };
        line(out, &self.header);
        out.push('|');
        for (i, width) in widths.iter().enumerate() {
            if i < self.text_columns {
                let _ = write!(out, " {} |", "-".repeat(*width));
            } else {
                // Right-align numbers; the colon takes one of the cells' columns.
                let _ = write!(out, " {}: |", "-".repeat(width.saturating_sub(1)));
            }
        }
        out.push('\n');
        for row in &self.rows {
            line(out, row);
        }
    }
}

struct Profile {
    /// Substring an operation name has to contain to be profiled. Operations
    /// that do not match still run (later operations depend on them), just
    /// unprofiled.
    filter: Option<String>,
    /// Directory to write one dhat JSON per profiled operation into.
    save_dir: Option<PathBuf>,
    measurements: Vec<Measurement>,
}

impl Profile {
    /// Runs `f` under a fresh dhat profiler and records its heap stats.
    fn measure<T>(
        &mut self,
        provider: &'static str,
        operation: impl Into<String>,
        f: impl FnOnce() -> T,
    ) -> T {
        let operation = operation.into();
        if let Some(filter) = &self.filter {
            if !operation.contains(filter.as_str()) {
                return f();
            }
        }

        let builder = dhat::Profiler::builder();
        let profiler = match &self.save_dir {
            Some(dir) => builder
                .file_name(dir.join(format!(
                    "{}-{}.json",
                    file_stem(provider),
                    file_stem(&operation)
                )))
                .build(),
            None => builder.testing().build(),
        };
        let out = f();
        let stats = dhat::HeapStats::get();
        drop(profiler);

        self.measurements.push(Measurement {
            provider: provider.to_owned(),
            operation,
            allocs: stats.total_blocks,
            bytes: stats.total_bytes,
            peak: stats.max_bytes,
            retained: stats.curr_bytes,
        });
        out
    }

    fn into_report(self) -> Report {
        Report {
            ciphersuite: format!("{CIPHERSUITE:?}"),
            payload_bytes: PAYLOAD.len(),
            measurements: self.measurements,
        }
    }
}

/// Turns a human-readable label into something safe for a file name.
fn file_stem(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn identity(name: &str) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(name.into());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    (credential_with_key, signer)
}

fn process(
    group: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
    message: MlsMessageOut,
) -> ProcessedMessageContent {
    let message: MlsMessageIn = message.into();
    let message = message
        .try_into_protocol_message()
        .expect("expected a protocol message");
    group
        .process_message(provider, message)
        .expect("failed to process message")
        .into_content()
}

/// Walks a 2-member group through its life cycle, profiling each operation.
fn profile_provider<P: OpenMlsProvider + Default>(
    profile: &mut Profile,
    provider_name: &'static str,
) {
    // One provider per member: they must not share storage.
    let alice_provider = P::default();
    let bob_provider = P::default();
    let (alice_credential, alice_signer) = identity("Alice");
    let (bob_credential, bob_signer) = identity("Bob");
    // Default wire format policy: outgoing messages are PrivateMessages.
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .build();

    let bob_key_package = profile.measure(provider_name, "key_package_build", || {
        KeyPackage::builder()
            .build(CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
            .expect("failed to build key package")
    });

    let mut alice_group = MlsGroup::new(&alice_provider, &alice_signer, &config, alice_credential)
        .expect("failed to create group");

    let welcome = profile.measure(provider_name, "add_members", || {
        let (_commit, welcome, _group_info) = alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(bob_key_package.key_package()),
            )
            .expect("failed to add member");
        welcome
    });
    profile.measure(provider_name, "merge_pending_commit (add)", || {
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("failed to merge add commit")
    });

    let ratchet_tree = alice_group.export_ratchet_tree();
    let mut bob_group = profile.measure(provider_name, "join_from_welcome", || {
        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome.into_welcome().expect("expected a welcome message");
        let processed_welcome =
            ProcessedWelcome::new_from_welcome(&bob_provider, config.join_config(), welcome)
                .expect("failed to process welcome");
        JoinBuilder::new(&bob_provider, processed_welcome)
            .with_ratchet_tree(ratchet_tree.into())
            .build()
            .expect("failed to build join")
            .into_group(&bob_provider)
            .expect("failed to join group")
    });

    // Warm-up round trip so the message path is measured in steady state.
    let message = alice_group
        .create_message(&alice_provider, &alice_signer, &PAYLOAD)
        .expect("failed to create warm-up message");
    process(&mut bob_group, &bob_provider, message);
    let message = bob_group
        .create_message(&bob_provider, &bob_signer, &PAYLOAD)
        .expect("failed to create warm-up message");
    process(&mut alice_group, &alice_provider, message);

    // Application message path.
    let message = profile.measure(provider_name, "create_message", || {
        alice_group
            .create_message(&alice_provider, &alice_signer, &PAYLOAD)
            .expect("failed to create message")
    });
    let content = profile.measure(provider_name, "process_message", || {
        process(&mut bob_group, &bob_provider, message)
    });
    match content {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            assert_eq!(application_message.into_bytes(), PAYLOAD);
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // Commit path: Bob commits, Alice processes.
    let commit = profile.measure(provider_name, "self_update", || {
        bob_group
            .self_update(&bob_provider, &bob_signer, LeafNodeParameters::default())
            .expect("failed to self-update")
            .into_commit()
    });
    profile.measure(provider_name, "merge_pending_commit", || {
        bob_group
            .merge_pending_commit(&bob_provider)
            .expect("failed to merge pending commit")
    });
    let staged_commit = profile.measure(
        provider_name,
        "process_message (commit)",
        || match process(&mut alice_group, &alice_provider, commit) {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => staged_commit,
            other => panic!("expected a staged commit, got {other:?}"),
        },
    );
    profile.measure(provider_name, "merge_staged_commit", || {
        alice_group
            .merge_staged_commit(&alice_provider, *staged_commit)
            .expect("failed to merge staged commit")
    });

    assert_eq!(alice_group.epoch(), bob_group.epoch());
}

fn default_save_dir() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
    target.join("dhat")
}

/// Allocation baseline for the OpenMLS hot paths, measured with dhat.
#[derive(Parser)]
#[command(after_help = "\
Examples:
  cargo bench -p openmls --bench alloc
  cargo bench -p openmls --bench alloc -- --save-baseline allocs.json
  cargo bench -p openmls --bench alloc -- --baseline allocs.json
  cargo bench -p openmls --bench alloc -- --save process_message")]
struct Args {
    /// Write the results as JSON to FILE, for later comparison with --baseline.
    #[arg(long, value_name = "FILE")]
    save_baseline: Option<PathBuf>,

    /// Compare the results against the JSON written by --save-baseline.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Write one dhat JSON per profiled operation into DIR for the DHAT
    /// viewer. Defaults to `target/dhat` when DIR is omitted.
    #[arg(long, value_name = "DIR", num_args = 0..=1, default_missing_value = "")]
    save: Option<PathBuf>,

    /// Only profile operations whose name contains this string.
    filter: Option<String>,

    /// Passed by `cargo bench`; ignored.
    #[arg(long, hide = true)]
    bench: bool,
}

fn main() {
    let args = Args::parse();

    // Fail on a bad baseline path before spending time on profiling.
    let baseline = args.baseline.as_deref().map(Report::load);
    let save_dir = args.save.map(|dir| {
        if dir.as_os_str().is_empty() {
            default_save_dir()
        } else {
            dir
        }
    });
    if let Some(dir) = &save_dir {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed to create {}: {e}", dir.display()));
    }
    let mut profile = Profile {
        filter: args.filter,
        save_dir,
        measurements: Vec::new(),
    };

    // Single-threaded rayon: worker threads allocate asynchronously.
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .use_current_thread()
        .build_global()
        .expect("failed to initialize rayon");

    profile_provider::<OpenMlsRustCrypto>(&mut profile, "RustCrypto");
    #[cfg(feature = "libcrux-provider")]
    profile_provider::<openmls_libcrux_crypto::Provider>(&mut profile, "libcrux");

    if let Some(dir) = &profile.save_dir {
        println!("dhat profiles written to {}", dir.display());
    }
    let report = profile.into_report();
    println!();
    println!("{}", report.render(baseline.as_ref()));
    if let Some(path) = &args.save_baseline {
        report.save(path);
        println!("baseline written to {}", path.display());
    }
}
