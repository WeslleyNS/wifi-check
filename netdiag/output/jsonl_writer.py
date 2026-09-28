"""
Escritor de arquivo .jsonl rotativo para o modo 'collect --daemon'.

Cada linha do arquivo JSONL contém um DiagnosticReport serializado
com timestamp ISO8601, todas as métricas e o veredito do Módulo 3.

Integração Zabbix (pull passivo — sem push ativo):
    UserParameter=netdiag.verdict,tail -1 <output_file> | python3 -c \
        "import sys,json; print(json.loads(sys.stdin.read()).get('verdict','UNKNOWN'))"
    UserParameter=netdiag.health_score,tail -1 <output_file> | python3 -c \
        "import sys,json; print(json.loads(sys.stdin.read()).get('health_score',0))"
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from netdiag.models import DiagnosticReport

logger = logging.getLogger("netdiag.output.jsonl_writer")

DEFAULT_OUTPUT_FILE = "netdiag-collect.jsonl"
BYTES_PER_MB = 1_048_576


class JsonlWriter:
    """
    Escritor de arquivo .jsonl com rotação por tamanho.

    Cada chamada a `write()` serializa um DiagnosticReport como uma linha JSON
    e acrescenta ao arquivo de saída. Quando o arquivo atinge `max_size_mb`,
    é renomeado para .jsonl.1 (sobrescrevendo o anterior) e um novo arquivo
    é criado.
    """

    def __init__(
        self,
        output_file: Optional[str] = None,
        max_size_mb: int = 10,
    ) -> None:
        """
        Inicializa o escritor JSONL.

        Args:
            output_file: Caminho do arquivo .jsonl. Se None, usa DEFAULT_OUTPUT_FILE
                         no diretório de trabalho atual.
            max_size_mb: Tamanho máximo do arquivo antes da rotação (em MB).
        """
        self.output_path = Path(output_file or DEFAULT_OUTPUT_FILE).resolve()
        self.max_size_bytes = max_size_mb * BYTES_PER_MB
        logger.info("JsonlWriter inicializado: %s (max=%dMB)", self.output_path, max_size_mb)

    async def write(self, report: DiagnosticReport) -> None:
        """
        Serializa e grava um DiagnosticReport como linha JSON no arquivo.

        Verifica o tamanho antes de gravar e rotaciona se necessário.
        Operações de I/O são feitas com try/except para não travar o daemon.

        Args:
            report: DiagnosticReport a serializar e gravar.
        """
        try:
            self._rotate_if_needed()
            line = self._serialize_report(report)

            # Garantir que o diretório pai exista
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

            with self.output_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

            logger.debug("Linha gravada em %s (%d bytes)", self.output_path, len(line))

        except OSError as exc:
            logger.error("Erro ao gravar no arquivo JSONL '%s': %s", self.output_path, exc)
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro inesperado no JsonlWriter: %s", exc, exc_info=True)

    def _rotate_if_needed(self) -> None:
        """
        Verifica o tamanho do arquivo e executa a rotação se exceder o limite.

        Estratégia de rotação simples (mantém apenas 1 backup):
        - Renomeia `output.jsonl` → `output.jsonl.1` (sobrescreve se existir).
        - Um novo arquivo `output.jsonl` será criado na próxima escrita.
        """
        try:
            if not self.output_path.exists():
                return

            size = self.output_path.stat().st_size
            if size < self.max_size_bytes:
                return

            backup = self.output_path.with_suffix(self.output_path.suffix + ".1")
            if backup.exists():
                backup.unlink()

            self.output_path.rename(backup)
            logger.info(
                "Rotação: '%s' renomeado para '%s' (tamanho: %dMB)",
                self.output_path.name,
                backup.name,
                size // BYTES_PER_MB,
            )

        except OSError as exc:
            logger.error("Erro na rotação do arquivo JSONL: %s", exc)

    @staticmethod
    def _serialize_report(report: DiagnosticReport) -> str:
        """
        Serializa um DiagnosticReport para uma string JSON em linha única.

        Converte: datetimes → ISO8601, enums → valores string,
        dataclasses aninhados → dicts recursivos.

        O resultado é compacto (sem indentação) para o formato JSONL.

        Args:
            report: DiagnosticReport a serializar.

        Returns:
            String JSON sem quebras de linha internas.
        """
        def _to_serializable(obj: Any) -> Any:
            """Converte objetos complexos para tipos serializáveis em JSON."""
            if obj is None:
                return None
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "value"):  # enums
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):  # dataclasses
                return {
                    k: _to_serializable(v)
                    for k, v in obj.__dict__.items()
                }
            if isinstance(obj, list):
                return [_to_serializable(item) for item in obj]
            if isinstance(obj, dict):
                return {k: _to_serializable(v) for k, v in obj.items()}
            return obj

        data = _to_serializable(report)
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
