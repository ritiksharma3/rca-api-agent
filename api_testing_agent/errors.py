"""Tool exceptions and CLI exit-code semantics."""

from __future__ import annotations

# Exit codes (documented in README)
EXIT_OK = 0
EXIT_TESTS_FAILED = 1  # run completed; at least one test FAILED
EXIT_INVALID_INPUT = 2
EXIT_DISCOVERY = 3  # framework not identified / discovery failed or produced nothing
EXIT_MISSING_DEPENDENCY = 4
EXIT_TARGET = 5  # target connectivity failure / unsafe target
EXIT_AUTH = 6
EXIT_EXECUTION = 7  # Newman could not complete (timeout, invalid collection, crash)
EXIT_BLOCKED = 8  # run completed but nothing could be executed (all BLOCKED)
EXIT_INTERNAL = 70


class AgentError(Exception):
    exit_code = EXIT_INTERNAL
    kind = "internal_error"


class InvalidInputError(AgentError):
    exit_code = EXIT_INVALID_INPUT
    kind = "invalid_input"


class FrameworkNotIdentifiedError(AgentError):
    exit_code = EXIT_DISCOVERY
    kind = "framework_not_identified"


class DiscoveryError(AgentError):
    exit_code = EXIT_DISCOVERY
    kind = "discovery_failure"


class InvalidInventoryError(AgentError):
    exit_code = EXIT_DISCOVERY
    kind = "invalid_inventory"


class CollectionGenerationError(AgentError):
    exit_code = EXIT_EXECUTION
    kind = "collection_generation_failure"


class MissingDependencyError(AgentError):
    exit_code = EXIT_MISSING_DEPENDENCY
    kind = "missing_dependency"


class UnsafeTargetError(AgentError):
    exit_code = EXIT_TARGET
    kind = "unsafe_target"


class TargetConnectivityError(AgentError):
    exit_code = EXIT_TARGET
    kind = "target_connectivity"


class AuthenticationError(AgentError):
    exit_code = EXIT_AUTH
    kind = "authentication_failure"


class NewmanExecutionError(AgentError):
    exit_code = EXIT_EXECUTION
    kind = "newman_execution_failure"
