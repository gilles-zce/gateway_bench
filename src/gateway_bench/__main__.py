"""Point d'entrée : `python -m gateway_bench` ou `poetry run gateway-bench`."""
from __future__ import annotations

import sys

from .cli import run


def main(argv: list[str] | None = None) -> int:
    code = run(argv)
    if code is not None:
        return code
    # Import paresseux : Kivy ouvre une fenêtre à l'import ; la ligne de
    # commande et les tests n'en dépendent pas.
    from .gui.app import run_gui
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
