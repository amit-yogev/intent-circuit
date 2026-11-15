class IntentCircuitError(Exception):
    """Base class for all expected IntentCircuit errors."""


class ScenarioFileError(IntentCircuitError):
    """The scenario file is missing or is not valid JSON."""


class InvalidScenarioError(IntentCircuitError):
    """The scenario JSON has a missing field, wrong type, or unknown action."""


class InvalidPolicyError(IntentCircuitError):
    """The security policy file is missing or invalid."""