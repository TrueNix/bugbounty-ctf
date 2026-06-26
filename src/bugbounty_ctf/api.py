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
from bugbounty_ctf.agents import (
    AgentContext,
    AgentResult,
    BaseAgent,
    ExploitAgent,
    FuzzAgent,
    ReconAgent,
    ResearchAgent,
    create_agent,
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
    generate_ssrf_bypass_ips,
    get_aws_credentials,
    ip_to_decimal,
    ip_to_hex,
    ip_to_octal,
)
from bugbounty_ctf.failures import FailureType, RequestFailure, handle_failure
from bugbounty_ctf.flag_hunter import FlagHunter, hunt_flags
from bugbounty_ctf.forensics import ForensicsToolkit
from bugbounty_ctf.hypothesis import Hypothesis, HypothesisEngine
from bugbounty_ctf.knowledge import KnowledgeBase
from bugbounty_ctf.observations import Observation, ObservationStore, recommend_next_test
from bugbounty_ctf.orchestrator import Orchestrator, OrchestratorReport, PhaseResult
from bugbounty_ctf.post_exploit import PostExploit, post_exploit_enum
from bugbounty_ctf.pwn import PwnToolkit
from bugbounty_ctf.quick_tests import (
    map_surface,
    test_command_injection,
    test_ldap_injection,
    test_login_sqli,
    test_nosqli,
    test_path_traversal,
    test_ssrf,
    test_ssti,
)
from bugbounty_ctf.skill_runner import PhaseGuidance, SkillOrchestrator
from bugbounty_ctf.smuggling import SmugglingDetector
from bugbounty_ctf.ssrf_pivot import SSRFPivot

__all__ = [
    "AWSExploiter",
    "AgentContext",
    "AgentResult",
    "BaseAgent",
    "ChainContext",
    "CryptoToolkit",
    "DiffAnalysis",
    "ExploitAgent",
    "FailureType",
    "FlagHunter",
    "ForensicsToolkit",
    "FuzzAgent",
    "Hypothesis",
    "HypothesisEngine",
    "KnowledgeBase",
    "Observation",
    "ObservationStore",
    "Orchestrator",
    "OrchestratorReport",
    "PhaseGuidance",
    "PhaseResult",
    "PostExploit",
    "PwnToolkit",
    "ReconAgent",
    "RequestFailure",
    "ResearchAgent",
    "ResponseDiff",
    "SSRFPivot",
    "ScannerDB",
    "SecurityScanner",
    "SkillOrchestrator",
    "SmugglingDetector",
    "TestResult",
    "bypass_url_filter",
    "confirm_vulnerability",
    "create_agent",
    "decode_jwt",
    "derive_base_url",
    "detect_defenses",
    "detect_ssrf_filter",
    "enumerate_aws_metadata",
    "exploit_aws_credentials",
    "forge_jwt_alg_none",
    "forge_jwt_hs256",
    "generate_aws_presigned_url",
    "generate_ssrf_bypass_ips",
    "get_aws_credentials",
    "handle_failure",
    "hunt_flags",
    "ip_to_decimal",
    "ip_to_hex",
    "ip_to_octal",
    "map_surface",
    "post_exploit_enum",
    "recommend_next_test",
    "save_report",
    "test_command_injection",
    "test_file_upload",
    "test_graphql_alias_batch",
    "test_idor",
    "test_jwt_attacks",
    "test_ldap_injection",
    "test_login_sqli",
    "test_nosqli",
    "test_path_traversal",
    "test_pickle_deserialization",
    "test_race_condition",
    "test_ssrf",
    "test_ssti",
    "test_xss",
    "test_xxe",
    "test_yaml_deserialization",
]
