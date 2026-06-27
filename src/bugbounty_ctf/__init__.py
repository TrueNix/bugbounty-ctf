"""Bug Bounty & CTF Toolkit.

A Python toolkit for CTF challenges and authorized bug bounty hunting.
Black-box testing methodology — discover vulnerabilities through observation
and systematic testing, not by reading source code.

Multi-agent orchestration:
    from bugbounty_ctf import Orchestrator
    from bugbounty_ctf.knowledge import KnowledgeBase

    kb = KnowledgeBase()
    orch = Orchestrator("http://target/")
    report = orch.run()

Individual tests:
    from bugbounty_ctf import SecurityScanner
    scanner = SecurityScanner("http://target/", delay=0.5)
    scanner.scan_endpoint("http://target/login", method="POST", data={"user": "test"})
"""

from bugbounty_ctf.engine import ResponseDiff, SecurityScanner, TestResult
from bugbounty_ctf.orchestrator import Orchestrator

__version__ = "7.0.0"
__all__ = ["Orchestrator", "ResponseDiff", "SecurityScanner", "TestResult", "__version__"]
