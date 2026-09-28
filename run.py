#!/usr/bin/env python3
"""
Ponto de entrada para execução como script ou binário empacotado.

Usado pelo PyInstaller como entry-point via --onefile.
"""
from netdiag.main import main

if __name__ == "__main__":
    main()
