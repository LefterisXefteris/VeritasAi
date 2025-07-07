from models import CommandType, RiskLevel

DETECTION_PATTERNS = {
    # Original command patterns
    CommandType.SHELL: [
        {
            "pattern": r"rm\s+-rf\s+[/\\]",
            "severity": RiskLevel.CRITICAL,
            "description": "Recursive file deletion"
        },
        {
            "pattern": r"sudo\s+\w+",
            "severity": RiskLevel.HIGH,
            "description": "Elevated privileges"
        },
        {
            "pattern": r"chmod\s+777",
            "severity": RiskLevel.HIGH,
            "description": "Dangerous permissions"
        },
        {
            "pattern": r"shutdown\s+",
            "severity": RiskLevel.CRITICAL,
            "description": "System shutdown"
        },
        {
            "pattern": r"reboot",
            "severity": RiskLevel.HIGH,
            "description": "System restart"
        },
        {
            "pattern": r"kill\s+-9",
            "severity": RiskLevel.MEDIUM,
            "description": "Force kill process"
        }
    ],
    
    CommandType.CODE: [
        {
            "pattern": r"eval\s*\(",
            "severity": RiskLevel.HIGH,
            "description": "Dynamic code execution"
        },
        {
            "pattern": r"exec\s*\(",
            "severity": RiskLevel.HIGH,
            "description": "Code execution"
        },
        {
            "pattern": r"__import__\s*\(",
            "severity": RiskLevel.MEDIUM,
            "description": "Dynamic imports"
        },
        {
            "pattern": r"subprocess\.call",
            "severity": RiskLevel.HIGH,
            "description": "Subprocess execution"
        }
    ],
    
    CommandType.FILE_OP: [
        {
            "pattern": r"wget\s+http",
            "severity": RiskLevel.MEDIUM,
            "description": "File download"
        },
        {
            "pattern": r"curl\s+.*\s+>\s*\w+",
            "severity": RiskLevel.MEDIUM,
            "description": "Download to file"
        },
        {
            "pattern": r"scp\s+\w+",
            "severity": RiskLevel.MEDIUM,
            "description": "Secure copy"
        }
    ],
    
    CommandType.NETWORK: [
        {
            "pattern": r"nc\s+-[el]",
            "severity": RiskLevel.HIGH,
            "description": "Network listener"
        },
        {
            "pattern": r"ssh\s+\w+@",
            "severity": RiskLevel.MEDIUM,
            "description": "Remote connection"
        },
        {
            "pattern": r"telnet\s+",
            "severity": RiskLevel.MEDIUM,
            "description": "Telnet connection"
        }
    ],
    
    CommandType.SYSTEM: [
        {
            "pattern": r"format\s+[cd]:",
            "severity": RiskLevel.CRITICAL,
            "description": "Format drive"
        },
        {
            "pattern": r"dd\s+if=.*of=",
            "severity": RiskLevel.HIGH,
            "description": "Disk write operation"
        }
    ],

    # NEW: AI-specific threat patterns
    CommandType.PROMPT_INJECTION: [
        {
            "pattern": r"(?i)SYSTEM\s*INSTRUCTION|IGNORE\s*.*(PREVIOUS|ALL).*INSTRUCTION",
            "severity": RiskLevel.CRITICAL,
            "description": "Direct prompt injection attempt"
        },
        {
            "pattern": r"(?i)You\s+are\s+now|New\s+instructions|Override.*prompt",
            "severity": RiskLevel.HIGH,
            "description": "Identity override attempt"
        },
        {
            "pattern": r"(?i)---.*END.*MESSAGE.*---|HIDDEN\s*INSTRUCTION",
            "severity": RiskLevel.HIGH,
            "description": "Message boundary manipulation"
        },
        {
            "pattern": r"(?i)ACT\s+AS|ROLEPLAY\s+AS|PRETEND\s+TO\s+BE",
            "severity": RiskLevel.MEDIUM,
            "description": "Role manipulation attempt"
        },
        {
            "pattern": r"(?i)JAILBREAK|BYPASS.*SAFETY|IGNORE.*FILTER",
            "severity": RiskLevel.CRITICAL,
            "description": "Security bypass attempt"
        }
    ],

    CommandType.DATA_EXFILTRATION: [
        {
            "pattern": r"(?i)read.*contents.*\/etc\/|list.*environment.*variable",
            "severity": RiskLevel.CRITICAL,
            "description": "System data extraction"
        },
        {
            "pattern": r"(?i)show.*api.*key|display.*secret|reveal.*token",
            "severity": RiskLevel.CRITICAL,
            "description": "API key harvesting attempt"
        },
        {
            "pattern": r"curl.*POST.*\$\(.*\)|send.*data.*external",
            "severity": RiskLevel.CRITICAL,
            "description": "Data exfiltration command"
        },
        {
            "pattern": r"(?i)copy.*sensitive|backup.*credentials|export.*database",
            "severity": RiskLevel.HIGH,
            "description": "Sensitive data extraction"
        },
        {
            "pattern": r"(?i)email.*contents.*to|forward.*data.*to",
            "severity": RiskLevel.HIGH,
            "description": "Data forwarding attempt"
        }
    ],

    CommandType.SOCIAL_ENGINEERING: [
        {
            "pattern": r"(?i)legitimate.*request|authorized.*user|emergency.*override",
            "severity": RiskLevel.MEDIUM,
            "description": "Authority claim"
        },
        {
            "pattern": r"(?i)maintenance.*mode|debug.*purpose|testing.*environment",
            "severity": RiskLevel.MEDIUM,
            "description": "Technical justification"
        },
        {
            "pattern": r"(?i)urgent.*help|critical.*issue|immediate.*action",
            "severity": RiskLevel.LOW,
            "description": "Urgency manipulation"
        },
        {
            "pattern": r"(?i)administrator.*privilege|elevated.*access|special.*permission",
            "severity": RiskLevel.HIGH,
            "description": "Privilege escalation claim"
        }
    ],

    CommandType.IDENTITY_MANIPULATION: [
        {
            "pattern": r"(?i)forget.*previous.*role|reset.*your.*purpose",
            "severity": RiskLevel.HIGH,
            "description": "Role reset attempt"
        },
        {
            "pattern": r"(?i)you.*must.*now|your.*new.*role.*is",
            "severity": RiskLevel.HIGH,
            "description": "Forced role change"
        },
        {
            "pattern": r"(?i)switch.*to.*mode|activate.*personality",
            "severity": RiskLevel.MEDIUM,
            "description": "Mode switching attempt"
        },
        {
            "pattern": r"(?i)bypass.*restriction|disable.*safeguard",
            "severity": RiskLevel.CRITICAL,
            "description": "Safety bypass request"
        }
    ],

    CommandType.API_HARVESTING: [
        {
            "pattern": r"(?i)what.*api.*key|current.*token|access.*credential",
            "severity": RiskLevel.CRITICAL,
            "description": "Direct API key request"
        },
        {
            "pattern": r"(?i)environment.*variable.*key|config.*file.*secret",
            "severity": RiskLevel.HIGH,
            "description": "Configuration data request"
        },
        {
            "pattern": r"(?i)\.env.*content|database.*connection.*string",
            "severity": RiskLevel.HIGH,
            "description": "Environment file access"
        },
        {
            "pattern": r"(?i)authentication.*header|bearer.*token",
            "severity": RiskLevel.MEDIUM,
            "description": "Auth token request"
        }
    ],

    CommandType.PRIVILEGE_ESCALATION: [
        {
            "pattern": r"(?i)admin.*access|root.*permission|superuser.*mode",
            "severity": RiskLevel.CRITICAL,
            "description": "Administrative privilege request"
        },
        {
            "pattern": r"(?i)escalate.*privilege|gain.*access|unlock.*feature",
            "severity": RiskLevel.HIGH,
            "description": "Privilege escalation attempt"
        },
        {
            "pattern": r"(?i)override.*security|bypass.*authentication",
            "severity": RiskLevel.CRITICAL,
            "description": "Security override request"
        },
        {
            "pattern": r"(?i)temporary.*admin|emergency.*access|debug.*privilege",
            "severity": RiskLevel.HIGH,
            "description": "Temporary privilege request"
        }
    ]
}