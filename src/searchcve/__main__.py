"""Entrypoint for running SearchCVE as a module (`python -m searchcve`)."""

import sys
from searchcve.cli import main

if __name__ == "__main__":
    sys.exit(main())
