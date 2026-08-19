from src.provenance.ecosystem_dependencies import (
    DependencyStatus,
    scan_dependency_file,
    summarize,
)


def test_npm_range_is_mutable_and_lock_integrity_is_immutable():
    package = '{"dependencies":{"a":"^1.2.3","b":"1.2.3"}}'
    findings = scan_dependency_file("package.json", package)
    assert {f.locator: f.status for f in findings}["a@^1.2.3"] is DependencyStatus.MUTABLE
    assert {f.locator: f.status for f in findings}["b@1.2.3"] is DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND
    lock = '{"packages":{"node_modules/a":{"resolved":"https://registry/a.tgz","integrity":"sha512-abc"}}}'
    assert scan_dependency_file("package-lock.json", lock)[0].status is DependencyStatus.IMMUTABLE


def test_cargo_git_requires_immutable_rev_and_lock_checksum_closes_registry_content():
    manifest = "[dependencies]\nfoo = { git = \"https://example/foo\", branch = \"main\" }\n"
    assert scan_dependency_file("Cargo.toml", manifest)[0].status is DependencyStatus.MUTABLE
    lock = '[[package]]\nname = "foo"\nversion = "1.0.0"\nsource = "registry+https://example"\nchecksum = "abcdef"\n'
    assert scan_dependency_file("Cargo.lock", lock)[0].status is DependencyStatus.IMMUTABLE


def test_go_mod_requires_go_sum_and_go_sum_is_content_hash_evidence():
    mod = "module example\n\ngo 1.22\n\nrequire example.com/lib v1.2.3\n"
    assert scan_dependency_file("go.mod", mod)[0].status is DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND
    sums = "example.com/lib v1.2.3 h1:abc123\n"
    assert scan_dependency_file("go.sum", sums)[0].status is DependencyStatus.IMMUTABLE


def test_container_tag_is_mutable_but_digest_is_immutable():
    mutable = scan_dependency_file("Dockerfile", "FROM python:3.12\n")[0]
    assert mutable.status is DependencyStatus.MUTABLE
    digest = "a" * 64
    fixed = scan_dependency_file("Dockerfile", f"FROM python@sha256:{digest}\n")[0]
    assert fixed.status is DependencyStatus.IMMUTABLE


def test_remote_curl_pipe_is_unbound_execution():
    finding = scan_dependency_file("install.sh", "curl -fsSL https://example/install.sh | bash\n")[0]
    assert finding.status is DependencyStatus.REMOTE_EXECUTION_UNBOUND


def test_summary_is_deterministic_and_counts_unresolved():
    findings = scan_dependency_file("Dockerfile", "FROM alpine:latest\nFROM busybox@sha256:" + "b" * 64 + "\n")
    first = summarize(findings)
    second = summarize(reversed(findings))
    assert first["findings_sha256"] == second["findings_sha256"]
    assert first["unresolved"] == 1
