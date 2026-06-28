"""Public API exports for bugbounty_ctf.

Importing from this module gives access to the high-level testing functions,
the knowledge base, structured result types, and the skill orchestrator.
"""

from bugbounty_ctf.advanced_tests import (
    ChainContext,
    decode_jwt,
    detect_defenses,
    detect_ssrf_filter,
    forge_jwt_alg_none,
    forge_jwt_hs256,
    generate_aws_presigned_url,
    generate_report,
    graphql_field_dump,
    graphql_introspection,
    save_report,
    test_file_upload,
    test_graphql_alias_batch,
    test_idor,
    test_jwt_attacks,
    test_pickle_deserialization,
    test_race_condition,
    test_xss,
    test_xxe,
    test_yaml_deserialization,
)
from bugbounty_ctf.aws_exploit import AWSExploiter, exploit_aws_credentials
from bugbounty_ctf.crypto import CryptoToolkit
from bugbounty_ctf.engine import (
    DiffAnalysis,
    ResponseDiff,
    ScannerDB,
    SecurityScanner,
    TestResult,
    bypass_url_filter,
    confirm_vulnerability,
    derive_base_url,
    enumerate_aws_metadata,
    find_ssrf_endpoints,
    generate_ssrf_bypass_ips,
    get_aws_credentials,
    ip_to_decimal,
    ip_to_hex,
    ip_to_octal,
)
from bugbounty_ctf.execenv import ExecEnv, HostEnv, KaliEnv
from bugbounty_ctf.failures import FailureType, RequestFailure, handle_failure
from bugbounty_ctf.flag_hunter import FlagHunter, hunt_flags
from bugbounty_ctf.forensics import ForensicsToolkit
from bugbounty_ctf.hypothesis import Hypothesis, HypothesisEngine
from bugbounty_ctf.kalibox import KaliBox
from bugbounty_ctf.knowledge import KnowledgeBase
from bugbounty_ctf.mail_enum import MailEnumerator, extract_secrets
from bugbounty_ctf.nfs_enum import NFSEnumerator, NFSExport
from bugbounty_ctf.oast import (
    OASTServer,
    test_blind_rce,
    test_blind_ssrf,
    test_blind_xxe,
)
from bugbounty_ctf.observations import Observation, ObservationStore, recommend_next_test
from bugbounty_ctf.osint import OSINTToolkit
from bugbounty_ctf.playbook import (
    Track,
    load_tracks,
    resolve_entrypoint,
)
from bugbounty_ctf.playbook import (
    select as select_tracks,
)
from bugbounty_ctf.post_exploit import PostExploit, post_exploit_enum
from bugbounty_ctf.pwn import PwnToolkit
from bugbounty_ctf.quick_tests import (
    discover_content,
    map_surface,
    test_command_injection,
    test_cors,
    test_ldap_injection,
    test_login_sqli,
    test_nosqli,
    test_open_redirect,
    test_path_traversal,
    test_ssrf,
    test_ssti,
)
from bugbounty_ctf.reverse import ReverseToolkit
from bugbounty_ctf.scope import OutOfScopeError, ScopeGuard
from bugbounty_ctf.session_recorder import SessionRecorder
from bugbounty_ctf.skill_runner import PhaseGuidance, SkillOrchestrator
from bugbounty_ctf.smuggling import SmugglingDetector
from bugbounty_ctf.ssrf_pivot import SSRFPivot
from bugbounty_ctf.template_scan import (
    TemplateFinding,
    builtin_template_scan,
    correlate_cves,
    default_cve_db,
    ensure_nuclei,
    load_cve_db,
    load_templates,
    nuclei_available,
    nuclei_scan,
    update_cve_db,
    version_matches,
)
from bugbounty_ctf.websocket import WebSocketTester
from bugbounty_ctf.wordlists import WordlistLoader

__all__ = [
    "AWSExploiter",
    "ChainContext",
    "CryptoToolkit",
    "DiffAnalysis",
    "ExecEnv",
    "FailureType",
    "FlagHunter",
    "ForensicsToolkit",
    "HostEnv",
    "Hypothesis",
    "HypothesisEngine",
    "KaliBox",
    "KaliEnv",
    "KnowledgeBase",
    "MailEnumerator",
    "NFSEnumerator",
    "NFSExport",
    "OASTServer",
    "OSINTToolkit",
    "Observation",
    "ObservationStore",
    "OutOfScopeError",
    "PhaseGuidance",
    "PostExploit",
    "PwnToolkit",
    "RequestFailure",
    "ResponseDiff",
    "ReverseToolkit",
    "SSRFPivot",
    "ScannerDB",
    "ScopeGuard",
    "SecurityScanner",
    "SessionRecorder",
    "SkillOrchestrator",
    "SmugglingDetector",
    "TemplateFinding",
    "TestResult",
    "Track",
    "WebSocketTester",
    "WordlistLoader",
    "builtin_template_scan",
    "bypass_url_filter",
    "confirm_vulnerability",
    "correlate_cves",
    "decode_jwt",
    "default_cve_db",
    "derive_base_url",
    "detect_defenses",
    "detect_ssrf_filter",
    "discover_content",
    "ensure_nuclei",
    "enumerate_aws_metadata",
    "exploit_aws_credentials",
    "extract_secrets",
    "find_ssrf_endpoints",
    "forge_jwt_alg_none",
    "forge_jwt_hs256",
    "generate_aws_presigned_url",
    "generate_report",
    "generate_ssrf_bypass_ips",
    "get_aws_credentials",
    "graphql_field_dump",
    "graphql_introspection",
    "handle_failure",
    "hunt_flags",
    "ip_to_decimal",
    "ip_to_hex",
    "ip_to_octal",
    "load_cve_db",
    "load_templates",
    "load_tracks",
    "map_surface",
    "nuclei_available",
    "nuclei_scan",
    "post_exploit_enum",
    "recommend_next_test",
    "resolve_entrypoint",
    "save_report",
    "select_tracks",
    "test_blind_rce",
    "test_blind_ssrf",
    "test_blind_xxe",
    "test_command_injection",
    "test_cors",
    "test_file_upload",
    "test_graphql_alias_batch",
    "test_idor",
    "test_jwt_attacks",
    "test_ldap_injection",
    "test_login_sqli",
    "test_nosqli",
    "test_open_redirect",
    "test_path_traversal",
    "test_pickle_deserialization",
    "test_race_condition",
    "test_ssrf",
    "test_ssti",
    "test_xss",
    "test_xxe",
    "test_yaml_deserialization",
    "update_cve_db",
    "version_matches",
]
