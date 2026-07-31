"""Abstract base class for all protocol fuzzer modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Device:
    ip: str
    port: int
    protocol: str
    device_type: str = "unknown"
    firmware: str = "unknown"
    vendor: str = "unknown"
    model: str = "unknown"
    mac: Optional[str] = None  # L2 address for Ethernet-only devices (e.g. GOOSE)
    metadata: dict = field(default_factory=dict)

    def __str__(self):
        return f"{self.protocol.upper()} {self.ip}:{self.port} [{self.device_type}]"


@dataclass
class FuzzResult:
    case_id: str
    protocol: str
    target: str
    category: str
    description: str
    payload: Optional[bytes] = None
    response: Optional[bytes] = None
    anomaly: Optional[str] = None
    crash_indicator: bool = False
    response_decoded: Optional[dict] = None
    duration_ms: Optional[float] = None


# Anomaly types logged in FuzzResult.anomaly
ANOMALY_TIMEOUT = "timeout"
ANOMALY_EXCEPTION = "exception_response"
ANOMALY_MALFORMED_RESPONSE = "malformed_response"
ANOMALY_CONNECTION_RESET = "connection_reset"
ANOMALY_NO_RESPONSE = "no_response"
ANOMALY_UNEXPECTED_DATA = "unexpected_data"

# Standard fuzz categories shared across all protocol modules
CATEGORY_BOUNDARY = "boundary"
CATEGORY_INJECTION = "injection"
CATEGORY_TYPE_CONFUSION = "type_confusion"
CATEGORY_STATE_MACHINE = "state_machine"
CATEGORY_SEQUENCE = "sequence"
CATEGORY_TIMESTAMP = "timestamp"
CATEGORY_BINARY_CORRUPTION = "binary_corruption"
CATEGORY_AUTH = "auth"
CATEGORY_PROTOCOL_SPECIFIC = "protocol_specific"

STANDARD_CATEGORIES = [
    CATEGORY_BOUNDARY,
    CATEGORY_INJECTION,
    CATEGORY_TYPE_CONFUSION,
    CATEGORY_STATE_MACHINE,
    CATEGORY_SEQUENCE,
    CATEGORY_TIMESTAMP,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_AUTH,
    CATEGORY_PROTOCOL_SPECIFIC,
]

# Standard injection payloads applied to all string fields
INJECTION_STRINGS = [
    # Format strings
    "%s%s%s%s%s%s%s%s%s%s",
    "%n%n%n%n%n%n%n%n",
    "%x%x%x%x%x%x%x%x",
    # SQLi
    "' OR '1'='1",
    "'; DROP TABLE devices;--",
    "1; SELECT * FROM users",
    # XSS
    "<script>alert(1)</script>",
    "javascript:alert(document.cookie)",
    # Command injection
    "; ls -la",
    "| cat /etc/passwd",
    "`id`",
    "$(id)",
    # Path traversal
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # Long strings / buffer candidates
    "A" * 256,
    "A" * 1024,
    "A" * 4096,
    # Null bytes
    "\x00" * 32,
    "test\x00injection",
    # Unicode
    "￿" * 16,
    "𐀀",
]


class FuzzModule(ABC):
    """Abstract base for all protocol fuzzer modules.

    Subclasses must set PROTOCOL_NAME, DEFAULT_PORT, and FUZZ_CATEGORIES,
    and implement all abstract methods.
    """

    PROTOCOL_NAME: str = ""
    DEFAULT_PORT: int = 0
    FUZZ_CATEGORIES: list = []

    def __init__(self, target: Device, logger, delay: float = 0.1, seeds: list = None):
        self.target = target
        self.logger = logger
        self.delay = delay
        self.seeds = seeds or []
        self._case_counter = 0

    def _next_id(self) -> str:
        self._case_counter += 1
        return f"{self.PROTOCOL_NAME}-{self._case_counter:04d}"

    @abstractmethod
    def discover(self, interface: str, timeout: int = 30) -> list:
        """Passively or actively discover devices speaking this protocol.
        Returns a list of Device instances."""

    @abstractmethod
    def connect(self, target: Device) -> None:
        """Establish a session with the target device."""

    def establish_presence(self) -> None:
        """Register as a legitimate client where the protocol requires it
        (e.g., publish a BIRTH message, open a session). Default: no-op."""

    @abstractmethod
    def fuzz(self, categories: Optional[list] = None) -> list:
        """Run fuzz cases. If categories is None, run all FUZZ_CATEGORIES.
        Returns a list of FuzzResult."""

    @abstractmethod
    def close(self) -> None:
        """Tear down the connection cleanly."""

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """Return device identity information.

        active=True  — send a single benign identity probe (e.g. List Identity,
                        FC43 MEI, BACnet Who-Is). Risk: one extra packet per device.
        active=False — passive only: read OS ARP cache, lookup OUI. Zero packets.

        Override in each protocol module.  Default returns confidence='none'.
        """
        from core.fingerprint import fingerprint_from_oui
        return fingerprint_from_oui(self.target.ip)

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        """Re-send a previously recorded raw payload and return the response.
        Override in each protocol module for protocol-aware replay."""
        raise NotImplementedError(f"{self.PROTOCOL_NAME}: replay_payload not implemented.")

    def _resolve_categories(self, categories: Optional[list]) -> list:
        if categories is None:
            return self.FUZZ_CATEGORIES
        valid = [c for c in categories if c in self.FUZZ_CATEGORIES]
        invalid = [c for c in categories if c not in self.FUZZ_CATEGORIES]
        if invalid:
            import warnings
            warnings.warn(
                f"{self.PROTOCOL_NAME}: ignoring unknown categories: {invalid}. "
                f"Valid: {self.FUZZ_CATEGORIES}"
            )
        return valid
