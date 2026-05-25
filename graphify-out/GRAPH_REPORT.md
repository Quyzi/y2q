# Graph Report - /home/digbick/Documents/code/y2q  (2026-05-25)

## Corpus Check
- 156 files · ~113,216 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1524 nodes · 2680 edges · 143 communities (101 shown, 42 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 166 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_TUI App Logic|TUI App Logic]]
- [[_COMMUNITY_Filesystem Storage|Filesystem Storage]]
- [[_COMMUNITY_io_uring Storage|io_uring Storage]]
- [[_COMMUNITY_Cryptographic Envelope|Cryptographic Envelope]]
- [[_COMMUNITY_Error Handling|Error Handling]]
- [[_COMMUNITY_Core Architecture|Core Architecture]]
- [[_COMMUNITY_Key Derivation|Key Derivation]]
- [[_COMMUNITY_io_uring Operations|io_uring Operations]]
- [[_COMMUNITY_Tree & Diff|Tree & Diff]]
- [[_COMMUNITY_Session Management|Session Management]]
- [[_COMMUNITY_Copy Operations|Copy Operations]]
- [[_COMMUNITY_Metadata Index|Metadata Index]]
- [[_COMMUNITY_Storage Abstraction|Storage Abstraction]]
- [[_COMMUNITY_Server Configuration|Server Configuration]]
- [[_COMMUNITY_TUI Rendering|TUI Rendering]]
- [[_COMMUNITY_Config Utilities|Config Utilities]]
- [[_COMMUNITY_Object Format|Object Format]]
- [[_COMMUNITY_Work Generator|Work Generator]]
- [[_COMMUNITY_Client Library|Client Library]]
- [[_COMMUNITY_Display Utilities|Display Utilities]]
- [[_COMMUNITY_Remote Pane|Remote Pane]]
- [[_COMMUNITY_Core Library|Core Library]]
- [[_COMMUNITY_E2E Tests|E2E Tests]]
- [[_COMMUNITY_Client Models|Client Models]]
- [[_COMMUNITY_Query Parser|Query Parser]]
- [[_COMMUNITY_Benchmark Metrics|Benchmark Metrics]]
- [[_COMMUNITY_Output Formatting|Output Formatting]]
- [[_COMMUNITY_Lock Management|Lock Management]]
- [[_COMMUNITY_Progress Reporting|Progress Reporting]]
- [[_COMMUNITY_Search Features|Search Features]]
- [[_COMMUNITY_Streaming Guard|Streaming Guard]]
- [[_COMMUNITY_Admin Dashboard|Admin Dashboard]]
- [[_COMMUNITY_Keystore Slot|Keystore Slot]]
- [[_COMMUNITY_CLI Definitions|CLI Definitions]]
- [[_COMMUNITY_Local Pane|Local Pane]]
- [[_COMMUNITY_Object Generator|Object Generator]]
- [[_COMMUNITY_Bucket Handlers|Bucket Handlers]]
- [[_COMMUNITY_Auth State|Auth State]]
- [[_COMMUNITY_Benchmark Bench|Benchmark Bench]]
- [[_COMMUNITY_Auth Commands|Auth Commands]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]
- [[_COMMUNITY_Community 81|Community 81]]
- [[_COMMUNITY_Community 82|Community 82]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 86|Community 86]]
- [[_COMMUNITY_Community 87|Community 87]]
- [[_COMMUNITY_Community 89|Community 89]]
- [[_COMMUNITY_Community 90|Community 90]]
- [[_COMMUNITY_Community 91|Community 91]]
- [[_COMMUNITY_Community 92|Community 92]]
- [[_COMMUNITY_Community 95|Community 95]]
- [[_COMMUNITY_Community 96|Community 96]]
- [[_COMMUNITY_Community 97|Community 97]]
- [[_COMMUNITY_Community 98|Community 98]]
- [[_COMMUNITY_Community 99|Community 99]]
- [[_COMMUNITY_Community 100|Community 100]]
- [[_COMMUNITY_Community 101|Community 101]]
- [[_COMMUNITY_Community 102|Community 102]]
- [[_COMMUNITY_Community 103|Community 103]]
- [[_COMMUNITY_Community 104|Community 104]]
- [[_COMMUNITY_Community 105|Community 105]]
- [[_COMMUNITY_Community 106|Community 106]]
- [[_COMMUNITY_Community 107|Community 107]]
- [[_COMMUNITY_Community 108|Community 108]]
- [[_COMMUNITY_Community 114|Community 114]]
- [[_COMMUNITY_Community 116|Community 116]]
- [[_COMMUNITY_Community 122|Community 122]]
- [[_COMMUNITY_Community 141|Community 141]]
- [[_COMMUNITY_Community 142|Community 142]]

## God Nodes (most connected - your core abstractions)
1. `App` - 68 edges
2. `make_storage()` - 41 edges
3. `default_tokens_path()` - 40 edges
4. `print_json()` - 30 edges
5. `make_object()` - 29 edges
6. `FilesystemStorage` - 26 edges
7. `UringStorage` - 26 edges
8. `AnyStorage` - 23 edges
9. `client_from_alias()` - 22 edges
10. `build_client()` - 22 edges

## Surprising Connections (you probably didn't know these)
- `Admin CLI commands` --implements--> `Admin routes`  [EXTRACTED]
  README.md → docs/api.md
- `Dual storage backends` --implements--> `LockRegistry`  [INFERRED]
  README.md → docs/architecture.md
- `Observability stack` --implements--> `Observability config`  [EXTRACTED]
  CLAUDE.md → docs/configuration.md
- `decrypt_blob()` --calls--> `decrypt_meta()`  [INFERRED]
  crates/y2q-core/src/storage/index.rs → crates/y2q-core/src/crypto/metadata_key.rs
- `field_hmac()` --calls--> `prf()`  [INFERRED]
  crates/y2q-core/src/storage/index.rs → crates/y2q-core/src/crypto/metadata_key.rs

## Communities (143 total, 42 thin omitted)

### Community 0 - "TUI App Logic"
Cohesion: 0.06
Nodes (29): client_from_alias(), default_tokens_path(), admin_nav_and_actions(), admin_tab_cycle_and_exit(), App, browse_misc_keys(), browse_quit_and_pane_toggle(), build_client() (+21 more)

### Community 1 - "Filesystem Storage"
Cohesion: 0.08
Nodes (65): bucket_config_round_trips_and_defaults_empty(), bucket_usage_impl(), bucket_usage_sums_object_sizes(), cipher_metadata(), collect_obj_files(), compute_checksum(), create_bucket_impl(), create_bucket_persists_empty_bucket_in_listing() (+57 more)

### Community 2 - "io_uring Storage"
Cohesion: 0.13
Nodes (30): collect_obj_files(), delete_returns_object_and_makes_subsequent_get_not_found(), describe_missing_object_returns_not_found(), disk_backed_tempdir(), get_missing_object_returns_not_found(), get_range_returns_only_requested_slice(), get_range_works_on_large_object_with_tail(), invalid_bucket_is_rejected_before_dispatch() (+22 more)

### Community 3 - "Cryptographic Envelope"
Cohesion: 0.10
Nodes (41): bench_envelope_v1_decrypt(), bench_envelope_v1_encrypt(), build_header(), chunk_nonce(), decrypt(), decrypt_owned(), decrypt_owned_v1_roundtrip(), decrypt_owned_v1_tamper() (+33 more)

### Community 4 - "Error Handling"
Cohesion: 0.07
Nodes (33): handle(), partial_content(), range_not_satisfiable(), extract_labels(), extracts_lowercased_labels(), ignores_unrelated_headers(), limits(), rejects_each_reserved_name_case_insensitively() (+25 more)

### Community 5 - "Core Architecture"
Cohesion: 0.05
Nodes (48): Admin routes, Auth API routes, Error model, HEAD response headers, Object CRUD routes, PUT request headers, HTTP status codes, User CRUD routes (+40 more)

### Community 6 - "Key Derivation"
Cohesion: 0.08
Nodes (29): Argon2Params, default_argon2_params(), fast_params(), nonce_changes_each_wrap(), params_serialize_roundtrip(), unwrap_sk(), unwrap_with_kek(), wrap_sk() (+21 more)

### Community 7 - "io_uring Operations"
Cohesion: 0.10
Nodes (34): decrypt_meta(), derive_index_key(), derive_mek(), encrypt_decrypt_roundtrip(), encrypt_meta(), mek_slot_install_clear_reinstall(), mek_uses_v2_label(), MekKeys (+26 more)

### Community 8 - "Tree & Diff"
Cohesion: 0.07
Nodes (29): collect(), collect_remote(), run(), collect(), copy_one(), delete_one(), join_local(), join_prefix() (+21 more)

### Community 9 - "Session Management"
Cohesion: 0.08
Nodes (22): add_user(), AddUserRequest, apply_floor(), attempt_unwrap(), change_password(), ChangePasswordRequest, ListUsersResponse, login() (+14 more)

### Community 10 - "Copy Operations"
Cohesion: 0.11
Nodes (17): download(), has_glob(), make_client(), run(), upload_dir_files(), upload_file(), upload_glob(), upload_recursive() (+9 more)

### Community 11 - "Metadata Index"
Cohesion: 0.16
Nodes (16): cursor(), decode_label_suffix(), decrypt_blob(), encode_bucket_prefix(), encode_bucket_prefix_enc(), encode_label_key(), encode_label_key_enc(), encode_label_prefix() (+8 more)

### Community 13 - "Server Configuration"
Cohesion: 0.08
Nodes (7): AuthConfig, CryptoConfig, EncryptionParams, LogFormat, ServerConfig, StorageBackend, StorageConfig

### Community 14 - "TUI Rendering"
Cohesion: 0.17
Nodes (23): app(), draw(), focused_block(), render(), render_admin(), render_bucket_config_popup(), render_error_popup(), render_events_tab() (+15 more)

### Community 15 - "Config Utilities"
Cohesion: 0.16
Nodes (14): Alias, atomic_write(), check_permissions(), CliConfig, CliConfigRaw, config_dir(), default_config_path(), defaults_omitted_extras_emitted() (+6 more)

### Community 16 - "Object Format"
Cohesion: 0.20
Nodes (12): decode_detects_corrupted_crc_byte(), decode_detects_corrupted_payload_field(), decode_rejects_bad_magic(), decode_rejects_wrong_version(), encoded_size_is_fixed(), FormatError, Header, legacy_zero_data_offset_decodes_to_min() (+4 more)

### Community 17 - "Work Generator"
Cohesion: 0.19
Nodes (16): main(), run(), build_tls_options(), now_secs(), read_pem(), resolve_token(), spawn_refresh_task(), bench() (+8 more)

### Community 18 - "Client Library"
Cohesion: 0.13
Nodes (6): build_rustls_client_config(), ClientConfig, NoVerifier, parse_client_identity(), TlsOptions, Y2qClient

### Community 19 - "Display Utilities"
Cohesion: 0.22
Nodes (13): AppState, DisplayMsg, particle_bar_spans(), Phase, plain_fallback(), push_cap(), render(), render_particle_bar() (+5 more)

### Community 20 - "Remote Pane"
Cohesion: 0.12
Nodes (4): obj(), RemoteEntry, RemoteLevel, RemotePane

### Community 21 - "Core Library"
Cohesion: 0.11
Nodes (15): BucketConfig, CacheRebuildStatus, CipherMetadata, DirtyEntry, Error, Listing, ListOptions, ListPage (+7 more)

### Community 22 - "E2E Tests"
Cohesion: 0.23
Nodes (12): e2e_full_cli_flow(), e2e_tls_flow(), ensure_warp(), ensure_y2qd(), free_port(), gen_self_signed(), ok(), Server (+4 more)

### Community 23 - "Client Models"
Cohesion: 0.11
Nodes (17): AddUserRequest, BucketConfig, ChangePasswordRequest, ClearStaleLocksResponse, ListBucketsResponse, ListOptions, ListPage, ListUsersResponse (+9 more)

### Community 24 - "Query Parser"
Cohesion: 0.17
Nodes (12): build_condition(), build_expr(), doc_example(), equality_and_inequality(), LabelQuery, labels(), MatchOp, parens_and_not() (+4 more)

### Community 25 - "Benchmark Metrics"
Cohesion: 0.16
Nodes (5): Aggregate, classify_http_error(), OpHistograms, OpRecord, Segment

### Community 26 - "Output Formatting"
Cohesion: 0.15
Nodes (8): run(), run(), run(), fmt_ns(), fmt_ns_formats_timestamp(), OutputMode, print_table(), print_table_empty_is_noop()

### Community 27 - "Lock Management"
Cohesion: 0.25
Nodes (8): acquire_and_release(), check_not_locked_reflects_state(), cutoff_boundary_is_strict_less_than(), different_keys_are_independent(), list_and_clear_stale(), LockGuard, LockRegistry, StaleLock

### Community 28 - "Progress Reporting"
Cohesion: 0.16
Nodes (3): PlainProgressReporter, TuiProgressReporter, fmt_bytes()

### Community 29 - "Search Features"
Cohesion: 0.18
Nodes (14): Listing routes, Label search queries, Search query language, Search error codes, Formal PEG grammar, HTTP search equivalent, Missing-label semantics, Search operators (+6 more)

### Community 30 - "Streaming Guard"
Cohesion: 0.22
Nodes (3): now_nanos(), UringStreamingPutGuard, UringStreamingWriter

### Community 31 - "Admin Dashboard"
Cohesion: 0.15
Nodes (4): EventsView, LocksView, MetricsView, RebuildView

### Community 32 - "Keystore Slot"
Cohesion: 0.21
Nodes (4): KeystoreSlot, RwLock, RwLock<T>, State

### Community 33 - "CLI Definitions"
Cohesion: 0.17
Nodes (11): Cli, Commands, AdminCmd, AliasCmd, AttributeCmd, EncryptCmd, LocksCmd, QuotaCmd (+3 more)

### Community 36 - "Bucket Handlers"
Cohesion: 0.20
Nodes (6): BucketConfig, BucketConfigBody, CreateBucketResponse, DeleteBucketResponse, get_config(), set_config()

### Community 37 - "Auth State"
Cohesion: 0.20
Nodes (3): AttemptState, AuthState, LoginAttempts

### Community 38 - "Benchmark Bench"
Cohesion: 0.44
Nodes (9): Backend, backends(), bench_get(), bench_get_range(), bench_put(), bench_put_best_effort(), configure_for_size(), scratch_dir() (+1 more)

### Community 39 - "Auth Commands"
Cohesion: 0.29
Nodes (7): run(), login(), logout(), passwd(), prompt_password(), run(), resolve_config_path()

### Community 40 - "Community 40"
Cohesion: 0.27
Nodes (7): make(), remove(), ping(), ready(), format_ts(), run(), print_json()

### Community 41 - "Community 41"
Cohesion: 0.29
Nodes (5): bucket_of(), bucket_of_parses_alias_bucket(), parse_size(), run_encrypt(), run_quota()

### Community 42 - "Community 42"
Cohesion: 0.20
Nodes (4): MixedWeights, ObjSize, RunConfig, WorkloadConfig

### Community 43 - "Community 43"
Cohesion: 0.29
Nodes (5): content_length(), stream(), trace_middleware(), TraceEvent, TraceHub

### Community 44 - "Community 44"
Cohesion: 0.22
Nodes (9): Observability routes, Prometheus metrics, Per-request X-Request-ID, Cargo features, Observability stack, Observability config, Pyroscope profiling config, Metrics operations (+1 more)

### Community 45 - "Community 45"
Cohesion: 0.39
Nodes (7): ansi_status(), format_trace_ts(), locks(), make_client(), rebuild(), status_color(), trace()

### Community 47 - "Community 47"
Cohesion: 0.22
Nodes (5): AdminTab, ConfirmAction, FocusedPane, InputAction, Mode

### Community 48 - "Community 48"
Cohesion: 0.25
Nodes (3): CpEndpoint, remote_path_variants(), RemotePath

### Community 49 - "Community 49"
Cohesion: 0.64
Nodes (7): bench_lookup(), bench_scan(), bench_upsert(), bench_upsert_best_effort(), make_meta(), open_index(), populate()

### Community 51 - "Community 51"
Cohesion: 0.61
Nodes (7): list(), parse_kv(), remove(), run_attribute(), run_tag(), set(), split_target()

### Community 52 - "Community 52"
Cohesion: 0.25
Nodes (7): Cli, Commands, AnalyzeArgs, CleanupArgs, MixedArgs, PrepareArgs, WorkloadArgs

### Community 53 - "Community 53"
Cohesion: 0.25
Nodes (7): ActixConfig, default_backlog(), default_client_disconnect_timeout_secs(), default_client_request_timeout_secs(), default_keep_alive_secs(), default_max_connections(), default_shutdown_timeout_secs()

### Community 54 - "Community 54"
Cohesion: 0.25
Nodes (6): Argon2Config, default_argon2_m_cost_kib(), default_argon2_p_cost(), default_argon2_t_cost(), default_log_filter(), ObservabilityConfig

### Community 56 - "Community 56"
Cohesion: 0.36
Nodes (4): particle_bar_spans(), render(), TransferEntry, TransferStatus

### Community 58 - "Community 58"
Cohesion: 0.57
Nodes (6): cat(), has_glob(), make_client(), require_bucket_key(), rm(), stat()

### Community 59 - "Community 59"
Cohesion: 0.38
Nodes (4): client_config_from_alias(), read_pem(), tls_override(), TlsOverride

### Community 61 - "Community 61"
Cohesion: 0.29
Nodes (5): coerce_cli_value(), Config, insert_nested(), LabelLimits, validate_envelope_chunk_size()

### Community 62 - "Community 62"
Cohesion: 0.38
Nodes (5): main(), ApiDoc, IgnoreBrokenPipe, print_first_run_password(), SecurityAddon

### Community 63 - "Community 63"
Cohesion: 0.43
Nodes (4): copy(), delete(), head(), rename()

### Community 68 - "Community 68"
Cohesion: 0.33
Nodes (3): ListObjectsResponse, ListQuery, MetadataView

### Community 69 - "Community 69"
Cohesion: 0.40
Nodes (3): RebuildStartResponse, RebuildStatusResponse, status()

### Community 71 - "Community 71"
Cohesion: 0.67
Nodes (5): build_provider(), build_server_config(), load_certs(), load_client_roots(), load_private_key()

### Community 74 - "Community 74"
Cohesion: 0.60
Nodes (3): Authenticated, extract_authenticated(), parse_bearer()

### Community 77 - "Community 77"
Cohesion: 0.50
Nodes (3): CliError, exit_codes_per_variant(), msg()

### Community 79 - "Community 79"
Cohesion: 0.83
Nodes (3): main(), run(), dispatch_rest()

### Community 80 - "Community 80"
Cohesion: 0.50
Nodes (3): Event, RemoteFetchPath, RemoteFetchResult

### Community 82 - "Community 82"
Cohesion: 0.83
Nodes (3): execute_op(), pick_op(), run_worker()

### Community 84 - "Community 84"
Cohesion: 0.50
Nodes (3): default_pyroscope_sample_rate(), default_pyroscope_url(), PyroscopeConfig

### Community 89 - "Community 89"
Cohesion: 0.50
Nodes (4): Required config fields, Server config, First-run workflow, Reverse proxy setup

## Knowledge Gaps
- **163 isolated node(s):** `allow`, `DirtyEntry`, `Metadata`, `SyncLevel`, `PutOptions` (+158 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **42 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `print_json()` connect `Community 40` to `Community 58`, `Community 39`, `Community 8`, `Community 41`, `Community 10`, `Community 45`, `Community 51`, `Community 26`, `Community 92`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **Why does `default_tokens_path()` connect `Community 0` to `Community 39`, `Community 10`, `Community 45`, `Community 15`, `Community 17`, `Community 58`, `Community 92`?**
  _High betweenness centrality (0.017) - this node is a cross-community bridge._
- **Why does `client_from_alias()` connect `Community 0` to `Community 39`, `Community 10`, `Community 45`, `Community 58`, `Community 59`, `Community 92`?**
  _High betweenness centrality (0.007) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `default_tokens_path()` (e.g. with `make_client()` and `run()`) actually correct?**
  _`default_tokens_path()` has 38 INFERRED edges - model-reasoned connections that need verification._
- **Are the 29 inferred relationships involving `print_json()` (e.g. with `run()` and `upload_single()`) actually correct?**
  _`print_json()` has 29 INFERRED edges - model-reasoned connections that need verification._
- **What connects `allow`, `DirtyEntry`, `Metadata` to the rest of the system?**
  _163 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.061386138613861385 - nodes in this community are weakly interconnected._