"""Hybrid key exchange recommendations use the standardized TLS group name.

X25519MLKEM768 is TLS supported group 4588 (0x11EC), defined in RFC 10024.
The pre-standard Kyber groups (X25519Kyber768Draft00 is 25497, 0x6399) are
marked obsolete in the IANA registry, and Chrome stopped offering them in
Chrome 131.
"""

import re
from pathlib import Path

from typer.testing import CliRunner

from pqc_bench.cli import app
from pqc_bench.data.critical_infrastructure import (
    SECTOR_PROFILES,
    get_sector_recommendation,
)
from pqc_bench.data.libraries import (
    HYBRID_MODES,
    LIBRARIES,
    get_hybrid_mode,
    get_recommended_hybrid_for_kem,
)
from pqc_bench.data.threat_model import DATA_PROFILES, DataClassification, assess_sndl_risk

KYBER_GROUP = re.compile(r"kyber\d*draft|x25519[_-]?kyber|secp256r1kyber|ecdhe_kyber", re.IGNORECASE)
DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "pqc_bench" / "data"


def test_no_data_file_names_a_kyber_group() -> None:
    offenders = []
    for path in sorted(DATA_DIR.glob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if KYBER_GROUP.search(line):
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert offenders == []


def test_recommended_kem_hybrid_is_x25519mlkem768() -> None:
    mode = get_recommended_hybrid_for_kem()
    assert mode.id == "x25519-mlkem768"
    assert mode.name == "X25519MLKEM768"
    assert mode.ietf_draft == "RFC 10024"
    assert mode.chrome_support is True


def test_hybrid_mode_names() -> None:
    for key, mode in HYBRID_MODES.items():
        assert not KYBER_GROUP.search(key)
        assert not KYBER_GROUP.search(mode.name)


def test_library_hybrid_groups() -> None:
    for lib in LIBRARIES.values():
        if lib.algorithms is None:
            continue
        for group in lib.algorithms.hybrid_kem:
            assert not KYBER_GROUP.search(group), f"{lib.id}: {group}"
    for lib_id in ("aws-lc", "boringssl", "openssl-3.5", "wolfssl"):
        assert "X25519MLKEM768" in LIBRARIES[lib_id].algorithms.hybrid_kem, lib_id


def test_sector_hybrid_recommendations() -> None:
    for sector_id, profile in SECTOR_PROFILES.items():
        hybrid = profile.recommended_hybrid_kem
        assert hybrid is None or not KYBER_GROUP.search(hybrid), sector_id
        assert get_sector_recommendation(sector_id)["hybrid_kem"] == (hybrid or "X25519MLKEM768")


def test_cnsa_sector_hybrid_carries_ml_kem_1024() -> None:
    """A sector that requires CNSA 2.0 recommends a hybrid with its ML-KEM-1024."""
    cnsa_sectors = [
        profile
        for profile in SECTOR_PROFILES.values()
        if any(r.name == "CNSA 2.0" and r.pqc_requirement == "mandatory" for r in profile.regulations)
    ]
    assert cnsa_sectors
    for profile in cnsa_sectors:
        assert profile.recommended_kem == "ML-KEM-1024", profile.id
        assert get_sector_recommendation(profile.id)["hybrid_kem"] == "SecP384r1MLKEM1024", profile.id


def test_sector_command_space_hybrid_matches_kem() -> None:
    result = CliRunner().invoke(app, ["sector", "space_aerospace"])
    assert result.exit_code == 0
    assert "KEM: ML-KEM-1024" in result.output
    assert "Hybrid KEM: SecP384r1MLKEM1024" in result.output
    assert "X25519MLKEM768" not in result.output


def test_sndl_hybrid_recommendation() -> None:
    recommended = set()
    for profile_id, profile in DATA_PROFILES.items():
        assessment = assess_sndl_risk(profile_id)
        assert assessment is not None
        if assessment.recommended_hybrid:
            assert not KYBER_GROUP.search(assessment.recommended_hybrid), profile_id
            # The hybrid carries the same ML-KEM parameter set as the recommended algorithm.
            assert assessment.recommended_algorithm is not None, profile_id
            kem = assessment.recommended_algorithm.replace("-", "")
            assert assessment.recommended_hybrid.endswith(kem), profile_id
            expected = (
                "SecP384r1MLKEM1024" if profile.classification == DataClassification.TOP_SECRET else "X25519MLKEM768"
            )
            assert assessment.recommended_hybrid == expected, profile_id
            recommended.add(assessment.recommended_hybrid)
    assert recommended == {"X25519MLKEM768", "SecP384r1MLKEM1024"}


def test_threat_command_national_security_hybrid_matches_algorithm() -> None:
    result = CliRunner().invoke(app, ["threat", "--data-type", "national_security"])
    assert result.exit_code == 0
    assert "Recommended Hybrid Mode: SecP384r1MLKEM1024" in result.output
    assert "Recommended Algorithm: ML-KEM-1024" in result.output
    assert "X25519MLKEM768" not in result.output


def test_hybrid_command_names_the_standard_group() -> None:
    result = CliRunner().invoke(app, ["hybrid"])
    assert result.exit_code == 0
    assert "X25519MLKEM768" in result.output
    assert "Chrome 131" in result.output
    assert not KYBER_GROUP.search(result.output)


def test_recommended_hybrids_are_hybrid_modes() -> None:
    """Every hybrid KEM that sector and threat recommend is listed by the hybrid command."""
    names = {mode.name for mode in HYBRID_MODES.values()}
    recommended = {profile.recommended_hybrid_kem for profile in SECTOR_PROFILES.values()}
    for profile_id in DATA_PROFILES:
        assessment = assess_sndl_risk(profile_id)
        assert assessment is not None
        recommended.add(assessment.recommended_hybrid)
    recommended.discard(None)
    assert "SecP384r1MLKEM1024" in recommended
    assert recommended <= names


def test_hybrid_kem_libraries_list_the_group() -> None:
    for mode in HYBRID_MODES.values():
        if mode.kem_or_sig != "kem":
            continue
        assert mode.libraries, mode.id
        for lib_id in mode.libraries:
            algorithms = LIBRARIES[lib_id].algorithms
            assert algorithms is not None, lib_id
            assert mode.name in algorithms.hybrid_kem, f"{mode.id}: {lib_id}"


def test_secp384r1mlkem1024_mode() -> None:
    mode = get_hybrid_mode("SecP384r1MLKEM1024")
    assert mode is not None
    assert mode is get_hybrid_mode("secp384r1-mlkem1024")
    assert mode.classical_algorithm == "ECDH P-384"
    assert mode.pqc_algorithm == "ML-KEM-1024"
    assert "0x11ED" in mode.description
    # Client key share: uncompressed P-384 point and ML-KEM-1024 encapsulation key.
    assert mode.combined_size == 97 + 1568
    assert get_hybrid_mode("X25519MLKEM768") is HYBRID_MODES["x25519-mlkem768"]
    assert get_hybrid_mode("ml-kem-1024") is None


def test_hybrid_command_lists_secp384r1mlkem1024() -> None:
    result = CliRunner().invoke(app, ["hybrid"])
    assert result.exit_code == 0
    section = result.output.split("SecP384r1MLKEM1024", 1)[1].split("ECDSA P-256", 1)[0]
    assert "TLS group 4589, 0x11ED" in section
    assert "Classical: ECDH P-384" in section
    assert "PQC: ML-KEM-1024" in section
    assert "Libraries: OpenSSL 3.5+, wolfSSL" in section


def test_hybrid_tls_use_case_lists_secp384r1mlkem1024() -> None:
    """hybrid --use-case tls names each KEM hybrid with TLS support and no other hybrid mode."""
    result = CliRunner().invoke(app, ["hybrid", "--use-case", "tls"])
    assert result.exit_code == 0
    assert "SecP384r1MLKEM1024" in result.output
    for mode in HYBRID_MODES.values():
        listed = mode.kem_or_sig == "kem" and mode.tls_support
        assert (mode.name in result.output) is listed, mode.name


def test_explain_shows_a_hybrid_mode() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["explain", "SecP384r1MLKEM1024"])
    assert result.exit_code == 0
    assert "Unknown algorithm" not in result.output
    assert "PQC: ML-KEM-1024" in result.output
    assert "Libraries: OpenSSL 3.5+, wolfSSL" in result.output

    result = runner.invoke(app, ["explain", "no-such-mode"])
    assert result.exit_code == 1
    assert "Unknown algorithm: no-such-mode" in result.output
    assert "SecP384r1MLKEM1024" in result.output
