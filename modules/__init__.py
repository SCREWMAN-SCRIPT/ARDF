"""
modules/__init__.py
───────────────────
ARDF modules package.

Exports all major modules for use throughout the framework.
"""

# Core modules
from modules.logger import init_logger, get_logger, ARDFLogger
from modules.session import Session, SessionMode, SessionStatus, Finding, SeverityLevel

# Recon modules
from modules.recon import run_recon

# Validation modules
from modules.validate.sqli import SQLiValidator
from modules.validate.nosqli import NoSQLiValidator
from modules.validate.ldap import LDAPValidator
from modules.validate.cmdi import CMDIValidator
from modules.validate.code import CodeValidator
from modules.validate.xxe import XXEValidator
from modules.validate.xpath import XPathValidator
from modules.validate.path_traversal import PathTraversalValidator
from modules.validate.auth import AuthValidator
from modules.validate.session import SessionValidator
from modules.validate.jwt import JWTValidator
from modules.validate.oauth import OAuthValidator
from modules.validate.mfa import MFAValidator
from modules.validate.classifier import VulnerabilityClassifier

# Tool wrappers
from modules.tools.sqlmap_wrapper import SQLMapWrapper
from modules.tools.hydra_wrapper import HydraWrapper
from modules.tools.nmap_wrapper import NmapWrapper

# Stealth
from modules.stealth import get_stealth_engine, StealthEngine, StealthConfig, ScanMode

# Other modules
from modules.bypass import run_bypass
from modules.workflow import run_workflow
from modules.redteam import run_redteam
from modules.exploit import run_exploit
from modules.intel import run_intel
from modules.report import generate_report

__all__ = [
    # Core
    "init_logger", "get_logger", "ARDFLogger",
    "Session", "SessionMode", "SessionStatus", "Finding", "SeverityLevel",

    # Recon
    "run_recon",

    # Validation
    "SQLiValidator", "NoSQLiValidator", "LDAPValidator",
    "CMDIValidator", "CodeValidator", "XXEValidator",
    "XPathValidator", "PathTraversalValidator",
    "AuthValidator", "SessionValidator", "JWTValidator",
    "OAuthValidator", "MFAValidator", "VulnerabilityClassifier",

    # Tools
    "SQLMapWrapper", "HydraWrapper", "NmapWrapper",

    # Stealth
    "get_stealth_engine", "StealthEngine", "StealthConfig", "ScanMode",

    # Other
    "run_bypass", "run_workflow", "run_redteam",
    "run_exploit", "run_intel", "generate_report",
]