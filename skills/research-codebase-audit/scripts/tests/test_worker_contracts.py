"""Static locks for generated worker-contract shape and rule retention."""

from collections import defaultdict
import re

import regbuild as rb


builder = rb.load_script("build_worker_contracts")
REGISTERS = rb.SKILL_DIR / "references" / "registers.md"
PROMPTS = rb.SKILL_DIR / "references" / "prompts"

# Each cap is the role contract's share of the full readme, a guardrail against
# contract bloat rather than a frozen boundary.  U15 added the phase-table and
# block-coverage grammar to the shared `Shard format` section, which the slice
# table routes into every worker contract; the recheck contracts are the ones
# most dominated by routed shared sections, so `recheck_code` moved without
# gaining a single line of role-specific text.  Measured: 0.6094 before U15
# against a 0.61 cap — already at the ceiling, 0.0006 of headroom — and 0.6239
# after.  Cap raised 0.61 -> 0.63 to match.
ROLE_SIZE_CAPS = {
    "planning": 0.72,
    "claims_first_pass": 0.62,
    "code_first_pass": 0.54,
    "second_read_claims": 0.70,
    "second_read_code": 0.50,
    "recheck_claims": 0.76,
    "recheck_code": 0.63,
    "merge_first_pass": 0.67,
    "merge_recheck": 0.78,
    "conventions": 0.39,
    "conventions_scan": 0.55,
    "cross_link": 0.66,
    "rewrite": 0.68,
}

CRITICAL_RULES = [
    {
        "label": "definition/use contract",
        "roles": ["claims_first_pass", "code_first_pass", "recheck_claims", "recheck_code"],
        "headings": ["Standing self-consistency checks"],
        "snippets": ["producer-defined set", "effective predicate"],
    },
    {
        "label": "empirical verification guardrail",
        "roles": [
            "code_first_pass",
            "second_read_claims",
            "second_read_code",
            "recheck_claims",
            "recheck_code",
        ],
        "headings": ["Empirical verification (establish behavior; do not infer it)"],
        "snippets": ["worker-retyped synthetic reproduction"],
    },
    {
        "label": "blocked-visible discipline",
        "roles": ["claims_first_pass", "recheck_claims"],
        "headings": ["Visibility test"],
        "snippets": ["Blocked Check", "visible material"],
    },
    {
        "label": "cheap-check completion and numerical caution",
        "roles": ["claims_first_pass", "code_first_pass", "recheck_claims", "recheck_code"],
        "headings": ["Cheap-check completion (mapped-closure discipline)"],
        "snippets": [
            "Caution default on a numerical disagreement",
            "unexplained numerical disagreement defaults",
        ],
    },
    {
        "label": "claim unit and enumerated procedure",
        "roles": ["planning", "claims_first_pass"],
        "headings": ["Claims register — `audit/claims_register.md`"],
        "snippets": [
            "Corollary — parameter-bearing steps of an enumerated procedure",
            "parameter-bearing step",
        ],
    },
    {
        "label": "quote qualifier and identifier anchoring",
        "roles": ["claims_first_pass", "recheck_claims"],
        "headings": [
            "Identifier anchoring on confirmation",
            "Quote-qualifier confirmation",
        ],
        "snippets": [
            "A claim that names specific identifiers",
            "The `confirmed` test is judged against the row's own verbatim Paper Quote",
        ],
    },
]

RULE_POINTERS = [
    (re.compile(r"Untrusted content \+ secrets"), ["Untrusted content", "Secret handling"]),
    (re.compile(r"claim-unit"), ["Claims register — `audit/claims_register.md`"]),
    (re.compile(r"`Paper Quote`"), ["Claims register — `audit/claims_register.md`"]),
    (re.compile(r"`Used in Text`"), ["Claims register — `audit/claims_register.md`"]),
    (re.compile(r"identifier-anchoring|Identifier anchoring"), ["Identifier anchoring on confirmation"]),
    (re.compile(r"quote-qualifier|Quote qualifiers"), ["Quote-qualifier confirmation"]),
    (re.compile(r"cheap-check|cheap static checks|caution default"), ["Cheap-check completion (mapped-closure discipline)"]),
    (re.compile(r"Empirical verification"), ["Empirical verification (establish behavior; do not infer it)"]),
    (re.compile(r"standing self-consistency checks"), ["Standing self-consistency checks"]),
    (re.compile(r"Shard write-up rules"), ["Shard format (worker outputs under `audit/_work/`, `audit/_code_errors/`, `audit/_recheck/`, `audit/_code_error_recheck/`)"]),
    (re.compile(r"row-lifecycle"), ["Row lifecycle: never delete, dedup on location+mechanism"]),
    (re.compile(r"verdict → register mapping|evidence levels"), ["Recheck vocabulary"]),
    (re.compile(r"full rule and worked examples"), ["Cross-link consistency (b7)"]),
    (re.compile(r"rewrite-pass columns"), ["Rewrite-pass columns"]),
]


def _build(tmp_path):
    audit_dir = tmp_path / "audit"
    artifacts = builder.build_artifacts(REGISTERS, audit_dir)
    contracts = builder.load_contract_mapping(REGISTERS.read_text(encoding="utf-8"))
    texts = {
        contract.role: (
            audit_dir / "_run" / "contracts" / f"{contract.role}.md"
        ).read_text(encoding="utf-8")
        for contract in contracts
    }
    return audit_dir, artifacts, contracts, texts


def test_generated_contracts_exist_for_all_roles(tmp_path):
    audit_dir, _artifacts, contracts, _texts = _build(tmp_path)
    roles = {contract.role for contract in contracts}

    assert roles == set(ROLE_SIZE_CAPS)
    for role in roles:
        assert (audit_dir / "_run" / "contracts" / f"{role}.md").is_file()


def test_role_contracts_stay_below_declared_size_caps(tmp_path):
    audit_dir, _artifacts, contracts, _texts = _build(tmp_path)
    full_size = len((audit_dir / "audit_readme.md").read_text(encoding="utf-8"))

    for contract in contracts:
        path = audit_dir / "_run" / "contracts" / f"{contract.role}.md"
        ratio = len(path.read_text(encoding="utf-8")) / full_size
        assert ratio <= ROLE_SIZE_CAPS[contract.role], (
            f"{contract.role} contract is {ratio:.2%} of full readme; "
            f"cap is {ROLE_SIZE_CAPS[contract.role]:.0%}"
        )


def test_critical_rules_are_retained_in_roles_that_need_them(tmp_path):
    _audit_dir, _artifacts, _contracts, texts = _build(tmp_path)

    for rule in CRITICAL_RULES:
        for role in rule["roles"]:
            text = texts[role]
            for heading in rule["headings"]:
                assert heading in text, f"{role} missing {heading} for {rule['label']}"
            for snippet in rule["snippets"]:
                assert snippet in text, f"{role} missing {snippet!r} for {rule['label']}"


def test_skeleton_named_rule_references_resolve_to_role_contract_sections(tmp_path):
    _audit_dir, _artifacts, contracts, texts = _build(tmp_path)
    roles_by_skeleton = defaultdict(list)
    for contract in contracts:
        for skeleton in contract.skeleton_files:
            roles_by_skeleton[skeleton].append(contract.role)

    for skeleton, roles in roles_by_skeleton.items():
        skeleton_text = (PROMPTS / skeleton).read_text(encoding="utf-8")
        for pattern, required_headings in RULE_POINTERS:
            if not pattern.search(skeleton_text):
                continue
            for role in roles:
                if (
                    skeleton == "recheck-cluster-worker.md"
                    and role == "recheck_code"
                    and pattern.pattern in {
                        "`Paper Quote`",
                        "`Used in Text`",
                        "identifier-anchoring|Identifier anchoring",
                    }
                ):
                    continue
                contract_text = texts[role]
                for heading in required_headings:
                    assert heading in contract_text, (
                        f"{skeleton} references {pattern.pattern!r}, but "
                        f"{role} contract lacks {heading!r}"
                    )
