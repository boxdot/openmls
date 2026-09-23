#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::{measurement::WallTime, BatchSize, BenchmarkGroup, BenchmarkId, Criterion};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

/// Identifies one measurement point of a benchmark group by the two dimensions
/// we vary: the crypto provider and the ciphersuite.
fn bench_id(provider_name: &str, ciphersuite: Ciphersuite) -> BenchmarkId {
    BenchmarkId::new(provider_name, format!("{ciphersuite:?}"))
}

fn criterion_key_package(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
            b.iter_with_setup(
                || {
                    let credential = BasicCredential::new(vec![1, 2, 3]);
                    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                    let credential_with_key = CredentialWithKey {
                        credential: credential.into(),
                        signature_key: signer.to_public_vec().into(),
                    };

                    (credential_with_key, signer)
                },
                |(credential_with_key, signer)| {
                    let _key_package = KeyPackage::builder()
                        .build(ciphersuite, provider, &signer, credential_with_key)
                        .expect("An unexpected error occurred.");
                },
            );
        });
    }
}

fn create_welcome(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
            b.iter_with_setup(
                || {
                    let alice_credential = BasicCredential::new("Alice".into());
                    let alice_signer =
                        SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                    let alice_credential_with_key = CredentialWithKey {
                        credential: alice_credential.into(),
                        signature_key: alice_signer.to_public_vec().into(),
                    };

                    let bob_credential = BasicCredential::new("Bob".into());
                    let bob_signer =
                        SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                    let bob_credential_with_key = CredentialWithKey {
                        credential: bob_credential.into(),
                        signature_key: bob_signer.to_public_vec().into(),
                    };
                    let bob_key_package = KeyPackage::builder()
                        .build(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential_with_key.clone(),
                        )
                        .expect("An unexpected error occurred.");

                    let mls_group_create_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // === Alice creates a group ===
                    let alice_group = MlsGroup::new(
                        provider,
                        &alice_signer,
                        &mls_group_create_config,
                        alice_credential_with_key.clone(),
                    )
                    .expect("An unexpected error occurred.");

                    (alice_signer, alice_group, bob_key_package)
                },
                |(alice_signer, mut alice_group, bob_key_package)| {
                    let _welcome = match alice_group.add_members(
                        provider,
                        &alice_signer,
                        core::slice::from_ref(bob_key_package.key_package()),
                    ) {
                        Ok((_, welcome, _)) => welcome,
                        Err(e) => panic!("Could not add member to group: {e:?}"),
                    };
                },
            );
        });
    }
}

fn join_group(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
            b.iter_with_setup(
                || {
                    let alice_credential = BasicCredential::new("Alice".into());
                    let alice_signer =
                        SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                    let alice_credential_with_key = CredentialWithKey {
                        credential: alice_credential.into(),
                        signature_key: alice_signer.to_public_vec().into(),
                    };

                    let bob_credential = BasicCredential::new("Bob".into());
                    let bob_signer =
                        SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                    let bob_credential_with_key = CredentialWithKey {
                        credential: bob_credential.into(),
                        signature_key: bob_signer.to_public_vec().into(),
                    };
                    let bob_key_package = KeyPackage::builder()
                        .build(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential_with_key.clone(),
                        )
                        .expect("An unexpected error occurred.");

                    let mls_group_create_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // === Alice creates a group ===
                    let mut alice_group = MlsGroup::new(
                        provider,
                        &alice_signer,
                        &mls_group_create_config,
                        alice_credential_with_key.clone(),
                    )
                    .expect("An unexpected error occurred.");

                    let welcome = match alice_group.add_members(
                        provider,
                        &alice_signer,
                        core::slice::from_ref(bob_key_package.key_package()),
                    ) {
                        Ok((_, welcome, _)) => welcome,
                        Err(e) => panic!("Could not add member to group: {e:?}"),
                    };

                    alice_group
                        .merge_pending_commit(provider)
                        .expect("error merging pending commit");

                    (alice_group, mls_group_create_config, welcome)
                },
                |(alice_group, mls_group_create_config, welcome)| {
                    let welcome: MlsMessageIn = welcome.into();
                    let welcome = welcome
                        .into_welcome()
                        .expect("expected the message to be a welcome message");
                    let processed_welcome = ProcessedWelcome::new_from_welcome(
                        provider,
                        mls_group_create_config.join_config(),
                        welcome,
                    )
                    .unwrap();
                    let _bob_group = JoinBuilder::new(provider, processed_welcome)
                        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
                        .replace_old_group()
                        .build()
                        .unwrap()
                        .into_group(provider)
                        .unwrap();
                },
            );
        });
    }
}

fn create_commit(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
            b.iter_with_setup(
                || {
                    let alice_credential = BasicCredential::new("Alice".into());
                    let alice_signer =
                        SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                    let alice_credential_with_key = CredentialWithKey {
                        credential: alice_credential.into(),
                        signature_key: alice_signer.to_public_vec().into(),
                    };

                    let bob_credential = BasicCredential::new("Bob".into());
                    let bob_signer =
                        SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                    let bob_credential_with_key = CredentialWithKey {
                        credential: bob_credential.into(),
                        signature_key: bob_signer.to_public_vec().into(),
                    };
                    let bob_key_package = KeyPackage::builder()
                        .build(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential_with_key.clone(),
                        )
                        .expect("An unexpected error occurred.");

                    let mls_group_create_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // === Alice creates a group ===
                    let mut alice_group = MlsGroup::new(
                        provider,
                        &alice_signer,
                        &mls_group_create_config,
                        alice_credential_with_key.clone(),
                    )
                    .expect("An unexpected error occurred.");

                    let welcome = match alice_group.add_members(
                        provider,
                        &alice_signer,
                        core::slice::from_ref(bob_key_package.key_package()),
                    ) {
                        Ok((_, welcome, _)) => welcome,
                        Err(e) => panic!("Could not add member to group: {e:?}"),
                    };

                    alice_group
                        .merge_pending_commit(provider)
                        .expect("error merging pending commit");

                    let welcome: MlsMessageIn = welcome.into();
                    let welcome = welcome
                        .into_welcome()
                        .expect("expected the message to be a welcome message");
                    let processed_welcome = ProcessedWelcome::new_from_welcome(
                        provider,
                        mls_group_create_config.join_config(),
                        welcome,
                    )
                    .unwrap();
                    let bob_group = JoinBuilder::new(provider, processed_welcome)
                        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
                        .replace_old_group()
                        .build()
                        .unwrap()
                        .into_group(provider)
                        .unwrap();

                    (bob_group, bob_signer)
                },
                |(mut bob_group, bob_signer)| {
                    let _ = bob_group
                        .self_update(provider, &bob_signer, LeafNodeParameters::default())
                        .unwrap();

                    bob_group
                        .merge_pending_commit(provider)
                        .expect("error merging pending commit");
                },
            );
        });
    }
}

const PAYLOAD: [u8; 100] = [0x42; 100];

/// Group sizes for the commit processing benchmark.
const GROUP_SIZES: [usize; 3] = [10, 100, 1000];

fn identity(ciphersuite: Ciphersuite, name: &str) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(name.into());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    (credential_with_key, signer)
}

fn into_protocol_message(message: MlsMessageOut) -> ProtocolMessage {
    MlsMessageIn::from(message)
        .try_into_protocol_message()
        .expect("expected a protocol message")
}

/// A member of a benchmark group, with its own provider.
struct Member<P> {
    provider: P,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

/// Alice creates a group with `size` members, Bob is the second one. The
/// others exist only as key packages.
fn alice_and_bob<P: OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
    config: &MlsGroupCreateConfig,
    size: usize,
) -> (Member<P>, Member<P>) {
    let alice_provider = P::default();
    let bob_provider = P::default();
    let others_provider = P::default();
    let (alice_credential, alice_signer) = identity(ciphersuite, "Alice");
    let (bob_credential, bob_signer) = identity(ciphersuite, "Bob");

    let mut key_packages = vec![KeyPackage::builder()
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("An unexpected error occurred.")
        .key_package()
        .clone()];
    for i in 2..size {
        let (credential, signer) = identity(ciphersuite, &format!("Member {i}"));
        let key_package = KeyPackage::builder()
            .build(ciphersuite, &others_provider, &signer, credential)
            .expect("An unexpected error occurred.");
        key_packages.push(key_package.key_package().clone());
    }

    let mut alice_group = MlsGroup::new(&alice_provider, &alice_signer, config, alice_credential)
        .expect("An unexpected error occurred.");
    let (_commit, welcome, _group_info) = alice_group
        .add_members(&alice_provider, &alice_signer, &key_packages)
        .expect("Could not add members to group");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("error merging pending commit");

    let welcome = MlsMessageIn::from(welcome)
        .into_welcome()
        .expect("expected the message to be a welcome message");
    let processed_welcome =
        ProcessedWelcome::new_from_welcome(&bob_provider, config.join_config(), welcome).unwrap();
    let bob_group = JoinBuilder::new(&bob_provider, processed_welcome)
        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
        .build()
        .unwrap()
        .into_group(&bob_provider)
        .unwrap();

    (
        Member {
            provider: alice_provider,
            signer: alice_signer,
            group: alice_group,
        },
        Member {
            provider: bob_provider,
            signer: bob_signer,
            group: bob_group,
        },
    )
}

fn create_message<P: OpenMlsProvider + Default>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
) {
    for &ciphersuite in P::default().crypto().supported_ciphersuites().iter() {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build();
        let (mut alice, _bob) = alice_and_bob::<P>(ciphersuite, &config, 2);
        group.bench_function(bench_id(provider_name, ciphersuite), |b| {
            b.iter(|| {
                alice
                    .group
                    .create_message(&alice.provider, &alice.signer, &PAYLOAD)
                    .expect("An unexpected error occurred.")
            });
        });
    }
}

fn process_message<P: OpenMlsProvider + Default>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
) {
    for &ciphersuite in P::default().crypto().supported_ciphersuites().iter() {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build();
        let (mut alice, mut bob) = alice_and_bob::<P>(ciphersuite, &config, 2);
        group.bench_function(bench_id(provider_name, ciphersuite), |b| {
            b.iter_batched(
                || {
                    let message = alice
                        .group
                        .create_message(&alice.provider, &alice.signer, &PAYLOAD)
                        .expect("An unexpected error occurred.");
                    into_protocol_message(message)
                },
                |message| {
                    bob.group
                        .process_message(&bob.provider, message)
                        .expect("An unexpected error occurred.")
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// Alice processes Bob's commit without merging it, so the same commit can be
/// processed in every iteration.
fn process_commit<P: OpenMlsProvider + Default>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    size: usize,
) {
    for &ciphersuite in P::default().crypto().supported_ciphersuites().iter() {
        // A commit in a PublicMessage can be processed repeatedly: it does not
        // consume a secret tree ratchet.
        let config = MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(ciphersuite)
            .build();
        let (mut alice, mut bob) = alice_and_bob::<P>(ciphersuite, &config, size);
        let commit = bob
            .group
            .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
            .expect("An unexpected error occurred.")
            .into_commit();
        let commit = into_protocol_message(commit);
        group.bench_function(bench_id(provider_name, ciphersuite), |b| {
            b.iter_batched(
                || commit.clone(),
                |commit| {
                    alice
                        .group
                        .process_message(&alice.provider, commit)
                        .expect("An unexpected error occurred.")
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// Runs `bench` against a criterion group named `name`.
///
/// All providers have to be benchmarked into the same open group: criterion
/// generates a group's summary plot from the ids collected while the group is
/// alive.
fn bench_group(
    c: &mut Criterion,
    name: &str,
    bench: impl FnOnce(&mut BenchmarkGroup<'_, WallTime>),
) {
    let mut group = c.benchmark_group(name);
    bench(&mut group);
    group.finish();
}

fn criterion_benchmark(c: &mut Criterion) {
    let rust_crypto = OpenMlsRustCrypto::default();
    #[cfg(feature = "libcrux-provider")]
    let libcrux = openmls_libcrux_crypto::Provider::default();

    // One group per operation, holding a measurement per provider and
    // ciphersuite, so the group summary plot compares both dimensions.
    bench_group(c, "KeyPackage create bundle", |group| {
        criterion_key_package(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        criterion_key_package(group, "libcrux", &libcrux);
    });
    bench_group(c, "Create a welcome message", |group| {
        create_welcome(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        create_welcome(group, "libcrux", &libcrux);
    });
    bench_group(c, "Join a group", |group| {
        join_group(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        join_group(group, "libcrux", &libcrux);
    });
    bench_group(c, "Create a commit", |group| {
        create_commit(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        create_commit(group, "libcrux", &libcrux);
    });
    bench_group(c, "Create an application message", |group| {
        create_message::<OpenMlsRustCrypto>(group, "RustCrypto");
        #[cfg(feature = "libcrux-provider")]
        create_message::<openmls_libcrux_crypto::Provider>(group, "libcrux");
    });
    bench_group(c, "Process an application message", |group| {
        process_message::<OpenMlsRustCrypto>(group, "RustCrypto");
        #[cfg(feature = "libcrux-provider")]
        process_message::<openmls_libcrux_crypto::Provider>(group, "libcrux");
    });
    for size in GROUP_SIZES {
        bench_group(c, &format!("Process a commit ({size} members)"), |group| {
            process_commit::<OpenMlsRustCrypto>(group, "RustCrypto", size);
            #[cfg(feature = "libcrux-provider")]
            process_commit::<openmls_libcrux_crypto::Provider>(group, "libcrux", size);
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
