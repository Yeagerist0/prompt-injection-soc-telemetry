"""Inspect AI packaging of the SOC-telemetry indirect prompt injection benchmark.

Deliberately does not import `inspect_task.task` at package import time:
`inspect_ai` is an optional extra (`pip install .[inspect]`), and importing it
here would make the rest of the test suite uncollectable on an install that
does not have it.

    from inspect_task.task import soc_telemetry_injection
"""
