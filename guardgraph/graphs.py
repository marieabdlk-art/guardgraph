from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DataExposureGraph:
    """Conceptual data-exposure graph for GuardGraph.

    Tracks user-controlled inputs, validation boundaries, and sensitive sinks.
    The current MVP analyzer materializes these nodes as endpoint facts rather
    than building a full persistent graph object.
    """

    inputs: list[dict[str, Any]] = field(default_factory=list)
    validators: list[dict[str, Any]] = field(default_factory=list)
    sinks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AccessBoundaryGraph:
    """Conceptual access-boundary graph for GuardGraph.

    Tracks authentication, role/permission checks, ownership checks, and
    framework-specific dependency boundaries.
    """

    auth_guards: list[dict[str, Any]] = field(default_factory=list)
    role_guards: list[dict[str, Any]] = field(default_factory=list)
    ownership_guards: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class StateMutationGraph:
    """Conceptual state-mutation graph for GuardGraph.

    Tracks state-changing endpoints and sensitive operations such as writes,
    deletes, payment actions, admin actions, and upload/plugin mutations.
    """

    endpoints: list[dict[str, Any]] = field(default_factory=list)
    operations: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class GuardGraphView:
    """Threefold structural view used by the analyzer.

    The analyzer currently operates on extracted facts, but this module names
    the three conceptual graph layers explicitly so the architecture remains
    visible and can be expanded into full graph objects later.
    """

    data_exposure: DataExposureGraph = field(default_factory=DataExposureGraph)
    access_boundary: AccessBoundaryGraph = field(default_factory=AccessBoundaryGraph)
    state_mutation: StateMutationGraph = field(default_factory=StateMutationGraph)
