"""
NetDiag Agent — Ponto de entrada principal.

Gerencia o CLI (argparse), orquestra os módulos via asyncio e
despacha para o modo doctor (one-shot) ou collect --daemon (contínuo).

Uso:
    netdiag doctor              # diagnóstico one-shot (~60s)
    netdiag collect --daemon    # monitoramento contínuo em loop
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import NoReturn

from netdiag.orchestrator import Orchestrator
from netdiag.utils.platform import detect_platform, check_privileges

# Forçar UTF-8 no stdout/stderr para evitar UnicodeEncodeError no Windows (cp1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Configuração de logging raiz
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("netdiag.main")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Constrói o parser de argumentos do NetDiag Agent.

    Returns:
        argparse.ArgumentParser: Parser configurado com subcomandos.
    """
    parser = argparse.ArgumentParser(
        prog="netdiag",
        description="NetDiag Agent — Diagnóstico e monitoramento de rede",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  netdiag doctor                  # diagnóstico completo (~60s)\n"
            "  netdiag collect --daemon        # monitoramento contínuo\n"
            "  netdiag collect --daemon --interval 60  # ciclo de 60s\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0-alpha",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Ativa saída de depuração detalhada.",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMANDO")

    # -----------------------------------------------------------------------
    # Subcomando: doctor
    # -----------------------------------------------------------------------
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Executa diagnóstico one-shot (~60s) e gera relatório HTML + TXT + ZIP.",
    )
    doctor_parser.add_argument(
        "--output-dir",
        metavar="DIRETÓRIO",
        default=None,
        help=(
            "Diretório de saída dos relatórios. "
            "Padrão: Desktop do usuário (com fallback automático)."
        ),
    )
    doctor_parser.add_argument(
        "--duration",
        type=int,
        default=60,
        metavar="SEGUNDOS",
        help="Duração da coleta em segundos (padrão: 60).",
    )

    # -----------------------------------------------------------------------
    # Subcomando: collect
    # -----------------------------------------------------------------------
    collect_parser = subparsers.add_parser(
        "collect",
        help="Executa coleta contínua em modo daemon, gravando em arquivo .jsonl rotativo.",
    )
    collect_parser.add_argument(
        "--daemon",
        action="store_true",
        required=True,
        help="Ativa o modo de monitoramento contínuo.",
    )
    collect_parser.add_argument(
        "--interval",
        type=int,
        default=30,
        metavar="SEGUNDOS",
        help="Intervalo entre ciclos de coleta em segundos (padrão: 30).",
    )
    collect_parser.add_argument(
        "--output-file",
        metavar="ARQUIVO",
        default=None,
        help=(
            "Caminho do arquivo .jsonl de saída. "
            "Padrão: netdiag-collect.jsonl no diretório de trabalho atual."
        ),
    )
    collect_parser.add_argument(
        "--max-size-mb",
        type=int,
        default=10,
        metavar="MB",
        help="Tamanho máximo do arquivo .jsonl antes da rotação (padrão: 10 MB).",
    )

    return parser


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

def main() -> NoReturn:
    """
    Ponto de entrada principal do NetDiag Agent.

    Responsável por:
    1. Parsear argumentos de linha de comando.
    2. Detectar plataforma e nível de privilégio.
    3. Instanciar o Orchestrator e disparar o modo correto.
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Detectar plataforma e privilégios antes de qualquer coleta
    platform_info = detect_platform()
    priv_info = check_privileges()

    logger.info(
        "Plataforma detectada: %s | Admin/root: %s",
        platform_info.name,
        priv_info.is_elevated,
    )

    if not priv_info.is_elevated:
        logger.warning(
            "Executando sem privilégios elevados. "
            "Algumas coletas serão ignoradas ou degradadas (veja o relatório)."
        )

    orchestrator = Orchestrator(
        platform=platform_info,
        privileges=priv_info,
        args=args,
    )

    try:
        if args.command == "doctor":
            asyncio.run(orchestrator.run_doctor())
        elif args.command == "collect":
            asyncio.run(orchestrator.run_collect())
    except KeyboardInterrupt:
        logger.info("Interrompido pelo usuário (Ctrl+C). Encerrando...")
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
