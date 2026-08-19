from src.provenance.python_dependencies import scan_install_commands, scan_requirements


def test_version_pin_without_hash_remains_provenance_gap():
    findings = scan_requirements("fastapi==0.115.0\n")
    assert len(findings) == 1
    assert findings[0].finding_type == "VERSION_PIN_WITHOUT_ARTIFACT_HASH"
    assert findings[0].classification == "PROVENANCE_GAP"


def test_unpinned_requirement_is_gap():
    findings = scan_requirements("pytest\n")
    assert findings[0].finding_type == "UNPINNED_OR_DYNAMIC_REQUIREMENT"


def test_direct_pip_install_is_gap():
    findings = scan_install_commands("pip install pytest\n", "workflow.yml")
    assert len(findings) == 1
    assert findings[0].finding_type == "DIRECT_PIP_INSTALL_WITHOUT_HASH_LOCK"


def test_requirements_file_install_is_delegated_to_requirements_scanner():
    assert scan_install_commands("pip install -r requirements.txt\n", "workflow.yml") == []
