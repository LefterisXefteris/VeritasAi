from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class CommandType(str, Enum):
    SHELL = "shell"
    CODE = "code"
    FILE_OP = "file_operation"
    NETWORK = "network"
    SYSTEM = "system"
    
    # New AI-specific threat categories
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    SOCIAL_ENGINEERING = "social_engineering"
    IDENTITY_MANIPULATION = "identity_manipulation"
    API_HARVESTING = "api_harvesting"
    PRIVILEGE_ESCALATION = "privilege_escalation"

class DetectedCommand(BaseModel):
    text: str
    command_type: CommandType
    severity: RiskLevel
    confidence: float  # 0.0 to 1.0
    pattern_matched: str
    context: Dict[str, Any] = {}

class AnalysisRequest(BaseModel):
    content: str
    context: Optional[Dict[str, Any]] = None
    policy: Optional[str] = "default"

class AnalysisResponse(BaseModel):
    id: str
    content: str
    detected_commands: List[DetectedCommand]
    risk_score: float
    risk_level: RiskLevel
    requires_review: bool
    blocked_commands: List[str]
    policy_applied: str
    timestamp: str
    file_analysis: Dict[str, Any]

class SecurityRule(BaseModel):
    name: str
    pattern: str
    action: str  # "BLOCK", "HUMAN_REVIEW", "ALLOW"
    severity: RiskLevel
    command_type: CommandType

class SecurityPolicy(BaseModel):
    name: str
    version: str
    description: str
    rules: List[SecurityRule]

class PolicyResult(BaseModel):
    requires_review: bool
    blocked_commands: List[str]
    applied_rules: List[str]