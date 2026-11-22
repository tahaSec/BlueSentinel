"""Application logging setup; log messages must not contain event payloads."""

import logging


def configure_logging(level: str = "INFO") -> None:
    """Configure concise operational logs on stderr."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
