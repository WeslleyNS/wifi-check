"""
setup.py — Placeholder para empacotamento com PyInstaller.

Este arquivo define os metadados do pacote para instalação via pip e
serve como referência para o processo de build do binário final.

Para gerar os binários (etapa futura, após código estar funcional):

  Windows (PowerShell, no mesmo diretório que run.py):
    pip install pyinstaller
    pyinstaller netdiag-windows.spec

  macOS (Terminal):
    pip install pyinstaller
    pyinstaller netdiag-macos.spec

Os .spec files controlam:
  - --onefile (binário único)
  - --name netdiag (ou netdiag.exe no Windows automaticamente)
  - --icon (ícone do executável — a definir)
  - --add-data para incluir recursos extras se necessário

Nota sobre macOS Gatekeeper:
  O binário gerado não será assinado por padrão. Usuários macOS precisarão
  executar: xattr -d com.apple.quarantine ./netdiag
  Isso está documentado no README.md.
"""

from setuptools import setup, find_packages

setup(
    name="netdiag-agent",
    version="0.1.0-alpha",
    description="Ferramenta multiplataforma de diagnóstico e monitoramento de rede",
    author="NetDiag Agent",
    python_requires=">=3.10",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "netdiag=netdiag.main:main",
        ],
    },
    # Sem dependências de terceiros — apenas built-ins do Python 3.10+
    # psutil é opcional (listado separado se estritamente necessário)
    install_requires=[],
    extras_require={
        "psutil": ["psutil>=5.9"],  # opcional para métricas extras de interface
    },
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
