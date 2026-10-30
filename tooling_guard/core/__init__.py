"""Review pipeline contracts: call facts, verdicts, reviewers, registry, pipeline.

Requirement: Reviewer Contract; Reviewer Registry; Concurrent Fan-Out and
Deny-Only Early Stop; Verdict Aggregation (openspec tasks 11.1-11.2).

Additive slice: nothing in production imports this package yet — task 11.3 is
what wires it in. Nothing here performs I/O, holds a store handle, owns a timer
or imports `astrbot.core.*`; each module is a contract another layer fills.

Modules are imported by name (`from tooling_guard.core.verdict import Verdict`)
instead of being re-exported here, so a later import cycle has nowhere to hide.
"""
