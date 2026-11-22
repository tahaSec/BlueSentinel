"""BlueSentinel executable entry point."""

from backend.cli.commands import run


def main(argv=None):
    """Run the analyst CLI and return its exit code."""
    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
