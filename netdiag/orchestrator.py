"""
Orquestrador assíncrono do NetDiag Agent.

Responsável por:
- Coordenar a execução paralela dos 3 módulos via asyncio.
- Gerenciar o loop de monitoramento contínuo (modo collect).
- Acionar a geração de relatório (modo doctor).
- Garantir que falhas em um módulo não derrubem os demais.
"""

from __future__ import annotations

import asyncio
import logging
from argparse import Namespace
from datetime import datetime, timezone
from typing import Optional

from netdiag.models import (
    DiagnosticReport,
    PassiveCollectionResult,
    PlatformInfo,
    PrivilegeInfo,
    SyntheticTestResult,
)
from netdiag.modules.passive_collector import PassiveCollector
from netdiag.modules.synthetic_tester import SyntheticTester
from netdiag.modules.decision_engine import DecisionEngine
from netdiag.output.report_generator import ReportGenerator
from netdiag.output.jsonl_writer import JsonlWriter
from netdiag.utils.platform import get_netdiag_logs_dir

logger = logging.getLogger("netdiag.orchestrator")


class Orchestrator:
    """
    Orquestrador principal do NetDiag Agent.

    Instancia e coordena os três módulos, gerencia o ciclo de vida
    assíncrono e delega a geração de output ao ReportGenerator/JsonlWriter.
    """

    def __init__(
        self,
        platform: PlatformInfo,
        privileges: PrivilegeInfo,
        args: Namespace,
    ) -> None:
        """
        Inicializa o orquestrador com as informações de plataforma e CLI.

        Args:
            platform: Informações sobre o SO detectado.
            privileges: Estado de privilégio e coletas ignoradas.
            args: Namespace com os argumentos de linha de comando parseados.
        """
        self.platform = platform
        self.privileges = privileges
        self.args = args

        self._passive_collector = PassiveCollector(platform=platform, privileges=privileges)
        self._synthetic_tester = SyntheticTester(platform=platform)
        self._decision_engine = DecisionEngine()
        self._report_generator = ReportGenerator(platform=platform)

    # -----------------------------------------------------------------------
    # Modo doctor (one-shot)
    # -----------------------------------------------------------------------

    async def run_doctor(self) -> None:
        """
        Executa o modo de diagnóstico one-shot.

        Fluxo:
        1. Roda coleta passiva e testes sintéticos em paralelo por `duration` segundos.
        2. Consolida os resultados no DecisionEngine.
        3. Gera relatório HTML, TXT resumo e ZIP com artefatos brutos.
        """
        duration: int = getattr(self.args, "duration", 60)
        output_dir: Optional[str] = getattr(self.args, "output_dir", None)

        logger.info("Iniciando modo 'doctor' (duração: %ds)...", duration)

        passive_result, synthetic_result = await self._run_parallel_collection(duration)

        report = self._decision_engine.evaluate(
            passive_result=passive_result,
            synthetic_result=synthetic_result,
            platform=self.platform,
            skipped_collections=self.privileges.skipped_collections,
        )

        await self._report_generator.generate_doctor_output(
            report=report,
            output_dir=output_dir,
        )

        self._print_summary(report)

    # -----------------------------------------------------------------------
    # Modo collect --daemon (contínuo)
    # -----------------------------------------------------------------------

    async def run_collect(self) -> None:
        """
        Executa o modo de monitoramento contínuo em daemon.

        Fluxo (loop infinito até SIGINT/Ctrl+C):
        1. A cada `interval` segundos, roda um ciclo de coleta passiva + sintética.
        2. Gera um DiagnosticReport via DecisionEngine.
        3. Serializa o relatório como linha JSON no arquivo .jsonl rotativo.
        4. Aguarda o próximo ciclo.

        Nota Zabbix:
            O arquivo .jsonl pode ser consumido por um UserParameter do zabbix_agent2.
            Exemplo de configuração em zabbix_agent2.conf:
                UserParameter=netdiag.verdict,tail -1 /var/log/netdiag/netdiag-collect.jsonl | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('verdict','UNKNOWN'))"
            Isso faz PULL passivo — o agente Zabbix lê o último veredito sem
            que o NetDiag precise enviar ativamente via zabbix_sender.
        """
        interval: int = getattr(self.args, "interval", 30)
        output_file: Optional[str] = getattr(self.args, "output_file", None)
        max_size_mb: int = getattr(self.args, "max_size_mb", 10)

        # Se output_file não foi especificado, salvar na pasta NetDiag-Logs do Desktop
        if not output_file:
            logs_dir = get_netdiag_logs_dir()
            output_file = str(logs_dir / "netdiag-collect.jsonl")

        logger.info(
            "Iniciando modo 'collect --daemon' (intervalo: %ds, arquivo: %s)...",
            interval,
            output_file,
        )
        print(f"\n  [DAEMON] Gravando coletas em: {output_file}")
        print(f"  [DAEMON] Para encerrar, pressione Ctrl+C\n")

        writer = JsonlWriter(output_file=output_file, max_size_mb=max_size_mb)

        while True:
            cycle_start = datetime.now(tz=timezone.utc)
            logger.debug("Iniciando ciclo de coleta em %s", cycle_start.isoformat())

            try:
                passive_result, synthetic_result = await self._run_parallel_collection(
                    duration=interval
                )

                report = self._decision_engine.evaluate(
                    passive_result=passive_result,
                    synthetic_result=synthetic_result,
                    platform=self.platform,
                    skipped_collections=self.privileges.skipped_collections,
                )

                await writer.write(report)

                logger.info(
                    "Ciclo concluído | Veredito: %s | Nota de saúde: %d/100",
                    report.verdict.value,
                    report.health_score,
                )

            except Exception as exc:  # noqa: BLE001
                # Falhas no ciclo não devem encerrar o daemon
                logger.error("Erro não esperado no ciclo de coleta: %s", exc, exc_info=True)

            # Aguardar até o próximo ciclo
            elapsed = (datetime.now(tz=timezone.utc) - cycle_start).total_seconds()
            wait_time = max(0.0, interval - elapsed)
            if wait_time > 0:
                await asyncio.sleep(wait_time)

    # -----------------------------------------------------------------------
    # Helpers privados
    # -----------------------------------------------------------------------

    async def _run_parallel_collection(
        self, duration: int
    ) -> tuple[Optional[PassiveCollectionResult], Optional[SyntheticTestResult]]:
        """
        Executa a coleta passiva (Módulo 1) e os testes sintéticos (Módulo 2)
        em paralelo usando asyncio.gather.

        Args:
            duration: Tempo máximo de espera para cada módulo (em segundos).

        Returns:
            Tupla (PassiveCollectionResult, SyntheticTestResult).
            Qualquer um dos valores pode ser None em caso de falha total do módulo.
        """
        passive_task = asyncio.create_task(
            self._run_passive_safe(duration),
            name="passive_collector",
        )
        synthetic_task = asyncio.create_task(
            self._run_synthetic_safe(duration),
            name="synthetic_tester",
        )

        passive_result, synthetic_result = await asyncio.gather(
            passive_task,
            synthetic_task,
            return_exceptions=False,
        )

        return passive_result, synthetic_result

    async def _run_passive_safe(
        self, duration: int
    ) -> Optional[PassiveCollectionResult]:
        """
        Wrapper que executa o PassiveCollector com timeout e captura de exceções.

        Args:
            duration: Timeout máximo em segundos.

        Returns:
            PassiveCollectionResult ou None em caso de falha.
        """
        try:
            return await asyncio.wait_for(
                self._passive_collector.collect(),
                timeout=float(duration),
            )
        except asyncio.TimeoutError:
            logger.warning("Coleta passiva atingiu timeout de %ds.", duration)
            return None
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro na coleta passiva: %s", exc, exc_info=True)
            return None

    async def _run_synthetic_safe(
        self, duration: int
    ) -> Optional[SyntheticTestResult]:
        """
        Wrapper que executa o SyntheticTester com timeout e captura de exceções.

        Args:
            duration: Timeout máximo em segundos.

        Returns:
            SyntheticTestResult ou None em caso de falha.
        """
        try:
            return await asyncio.wait_for(
                self._synthetic_tester.run_all(),
                timeout=float(duration),
            )
        except asyncio.TimeoutError:
            logger.warning("Testes sintéticos atingiram timeout de %ds.", duration)
            return None
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro nos testes sintéticos: %s", exc, exc_info=True)
            return None

    @staticmethod
    def _print_summary(report: DiagnosticReport) -> None:
        """
        Imprime um resumo rápido no stdout após o modo doctor.

        Args:
            report: Relatório consolidado para exibição.
        """
        print("\n" + "=" * 60)
        print(f"  NetDiag Agent — Resultado do Diagnóstico")
        print("=" * 60)
        print(f"  Veredito  : {report.verdict_description}")
        print(f"  Nota      : {report.health_score}/100 ({report.health_grade.value})")
        print(f"  Timestamp : {report.timestamp.strftime('%d/%m/%Y %H:%M:%S')}")
        if report.correlated_events:
            print(f"  Eventos   : {len(report.correlated_events)} evento(s) correlacionado(s)")
        if report.skipped_collections:
            print(f"  AVISO     : Coletas ignoradas por falta de privilégio:")
            for skipped in report.skipped_collections:
                print(f"              - {skipped}")
        print("=" * 60)
        print("  Relatório gerado. Verifique os arquivos de saída.")
        print("=" * 60 + "\n")
