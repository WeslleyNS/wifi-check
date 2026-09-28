"""
Módulo 3 — Motor de Decisão.

Aplica lógica de veredito hierárquica sobre os resultados dos Módulos 1 e 2,
calcula a nota de saúde (0-100) e correlaciona eventos passivos com
anomalias sintéticas (janela ±30s) para apontar causa provável.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from netdiag.models import (
    CorrelatedEvent,
    DiagnosticReport,
    HealthGrade,
    PassiveCollectionResult,
    PlatformInfo,
    SyntheticTestResult,
    VerdictCode,
    WifiEvent,
)

logger = logging.getLogger("netdiag.modules.decision_engine")

# ---------------------------------------------------------------------------
# Limiares de decisão
# ---------------------------------------------------------------------------
JITTER_THRESHOLD_MS: float = 30.0       # jitter máximo aceitável
PACKET_LOSS_THRESHOLD_PCT: float = 2.0  # perda máxima aceitável (%)
DNS_SLOW_THRESHOLD_MS: float = 500.0    # DNS lento acima deste valor
TCP_SLOW_THRESHOLD_MS: float = 1000.0   # TCP lento acima deste valor

# Janela de correlação temporal entre eventos passivos e anomalias sintéticas
CORRELATION_WINDOW_S: float = 30.0

# Descrições em PT-BR para cada veredito
_VERDICT_DESCRIPTIONS: dict[VerdictCode, str] = {
    VerdictCode.OK: "Rede funcionando normalmente — todos os testes passaram",
    VerdictCode.L2_ISOLATION: (
        "Link Down / Isolamento L2 — sem resposta do gateway. "
        "Verifique cabo, adaptador Wi-Fi e roteador."
    ),
    VerdictCode.NO_WAN: (
        "Sem acesso à WAN / rota inacessível — gateway responde mas sem Internet. "
        "Verifique o modem/link do provedor."
    ),
    VerdictCode.DNS_FAILURE: (
        "Degradação ou falha de resolução DNS — resolução lenta ou falhou. "
        "Tente trocar para 1.1.1.1 ou 8.8.8.8 manualmente."
    ),
    VerdictCode.FIREWALL_BLOCK: (
        "Bloqueio de firewall / rota assimétrica — DNS OK mas TCP 443 falhou ou lento. "
        "Verifique firewall do ISP, proxy ou bloqueio de porta."
    ),
    VerdictCode.NETWORK_INSTABILITY: (
        "Instabilidade de rede — jitter elevado ou perda de pacotes detectados. "
        "Possível sinal Wi-Fi fraco ou congestionamento de canal."
    ),
    VerdictCode.UNKNOWN: "Não foi possível determinar o estado da rede — dados insuficientes.",
}


class DecisionEngine:
    """
    Motor de decisão hierárquico do NetDiag Agent.

    Avalia os dados coletados pelos Módulos 1 e 2 e produz um DiagnosticReport
    com veredito, nota de saúde e correlações causa-efeito.

    Hierarquia de vereditos (para na primeira falha):
        1. Ping gateway falha         → L2_ISOLATION      (crítico)
        2. Ping externo falha         → NO_WAN             (crítico)
        3. DNS lento/falha            → DNS_FAILURE         (alto)
        4. TCP 443 falha/lento        → FIREWALL_BLOCK      (alto)
        5. Jitter > 30ms / perda > 2% → NETWORK_INSTABILITY (médio)
        6. Tudo OK                    → OK
    """

    def evaluate(
        self,
        passive_result: Optional[PassiveCollectionResult],
        synthetic_result: Optional[SyntheticTestResult],
        platform: Optional[PlatformInfo] = None,
        skipped_collections: Optional[list[str]] = None,
    ) -> DiagnosticReport:
        """
        Avalia os resultados e gera o DiagnosticReport final.

        Args:
            passive_result: Resultado do Módulo 1 (pode ser None se falhou).
            synthetic_result: Resultado do Módulo 2 (pode ser None se falhou).
            platform: Informações da plataforma de execução.
            skipped_collections: Coletas ignoradas por falta de privilégio.

        Returns:
            DiagnosticReport com veredito, nota de saúde e correlações.
        """
        timestamp = datetime.now(tz=timezone.utc)
        errors: list[str] = []

        if skipped_collections is None:
            skipped_collections = []

        # Propagar erros dos módulos upstream
        if passive_result and passive_result.errors:
            errors.extend(passive_result.errors)

        if synthetic_result is None:
            verdict = VerdictCode.UNKNOWN
            description = _VERDICT_DESCRIPTIONS[VerdictCode.UNKNOWN]
            errors.append("Módulo 2 (testes sintéticos) não retornou dados — veredito indeterminado.")
        else:
            verdict, description = self._apply_verdict_hierarchy(synthetic_result, errors)

        health_score = self._calculate_health_score(verdict, synthetic_result)
        health_grade = self._score_to_grade(health_score)
        correlated = self._correlate_events(passive_result, synthetic_result)

        logger.info(
            "Veredito: %s | Nota: %d/100 (%s) | Eventos correlacionados: %d",
            verdict.value,
            health_score,
            health_grade.value,
            len(correlated),
        )

        return DiagnosticReport(
            timestamp=timestamp,
            verdict=verdict,
            verdict_description=description,
            health_score=health_score,
            health_grade=health_grade,
            passive_result=passive_result,
            synthetic_result=synthetic_result,
            correlated_events=correlated,
            skipped_collections=skipped_collections,
            errors=errors,
            platform=platform,
        )

    # -----------------------------------------------------------------------
    # Hierarquia de veredito
    # -----------------------------------------------------------------------

    def _apply_verdict_hierarchy(
        self,
        synthetic: SyntheticTestResult,
        errors: list[str],
    ) -> tuple[VerdictCode, str]:
        """
        Aplica a lógica de veredito hierárquica.

        Para na primeira falha detectada, do nível mais grave para o menos grave.

        Args:
            synthetic: Resultado dos testes sintéticos.
            errors: Lista mutável onde observações são acrescentadas.

        Returns:
            Tupla (VerdictCode, descrição em PT-BR).
        """
        # 1. L2 — Ping ao gateway
        if not self._check_gateway_ping(synthetic):
            return VerdictCode.L2_ISOLATION, _VERDICT_DESCRIPTIONS[VerdictCode.L2_ISOLATION]

        # 2. WAN — Ping a alvos externos
        if not self._check_external_ping(synthetic):
            return VerdictCode.NO_WAN, _VERDICT_DESCRIPTIONS[VerdictCode.NO_WAN]

        # 3. DNS
        dns_ok, dns_slow = self._check_dns(synthetic)
        if not dns_ok or dns_slow:
            return VerdictCode.DNS_FAILURE, _VERDICT_DESCRIPTIONS[VerdictCode.DNS_FAILURE]

        # 4. TCP
        tcp_ok, tcp_slow = self._check_tcp(synthetic)
        if not tcp_ok or tcp_slow:
            return VerdictCode.FIREWALL_BLOCK, _VERDICT_DESCRIPTIONS[VerdictCode.FIREWALL_BLOCK]

        # 5. Instabilidade
        if self._check_instability(synthetic):
            return VerdictCode.NETWORK_INSTABILITY, _VERDICT_DESCRIPTIONS[VerdictCode.NETWORK_INSTABILITY]

        # 6. Tudo OK
        return VerdictCode.OK, _VERDICT_DESCRIPTIONS[VerdictCode.OK]

    def _check_gateway_ping(self, synthetic: SyntheticTestResult) -> bool:
        """
        Verifica se o ping ao gateway padrão foi bem-sucedido.

        Considera falha se: nenhum dado de gateway, ou 100% de perda de pacotes.

        Args:
            synthetic: Resultado dos testes sintéticos.

        Returns:
            True se o gateway respondeu ao ping.
        """
        if synthetic.ping is None or synthetic.ping.gateway is None:
            return False

        gw = synthetic.ping.gateway
        if gw.error and gw.packets_received == 0:
            return False

        # Se houve ao menos 1 pacote recebido, gateway está vivo
        return gw.packets_received > 0

    def _check_external_ping(self, synthetic: SyntheticTestResult) -> bool:
        """
        Verifica se pelo menos um alvo externo respondeu ao ping.

        Args:
            synthetic: Resultado dos testes sintéticos.

        Returns:
            True se ao menos um alvo externo (1.1.1.1 ou 8.8.8.8) respondeu.
        """
        if synthetic.ping is None:
            return False

        for target in synthetic.ping.external_targets:
            if target.packets_received > 0:
                return True

        return False

    def _check_dns(self, synthetic: SyntheticTestResult) -> tuple[bool, bool]:
        """
        Verifica se o DNS está respondendo e dentro do limiar de 500ms.

        Args:
            synthetic: Resultado dos testes sintéticos.

        Returns:
            Tupla (dns_ok, dns_slow).
            dns_ok=False → todos os resolvers falharam.
            dns_slow=True → todos os resolvers OK mas algum > 500ms.
        """
        if synthetic.dns is None or not synthetic.dns.queries:
            return False, False

        successful = [
            q for q in synthetic.dns.queries
            if q.resolved_ip is not None and q.response_time_ms is not None
        ]

        if not successful:
            return False, False

        # Checar se todos estão acima do limiar (se ao menos 1 resolver for rápido, é OK)
        fast_count = sum(
            1 for q in successful if q.response_time_ms <= DNS_SLOW_THRESHOLD_MS
        )

        dns_ok = True
        dns_slow = fast_count == 0  # todos os resolvers lentos

        return dns_ok, dns_slow

    def _check_tcp(self, synthetic: SyntheticTestResult) -> tuple[bool, bool]:
        """
        Verifica se o handshake TCP na porta 443 foi concluído em menos de 1s.

        Args:
            synthetic: Resultado dos testes sintéticos.

        Returns:
            Tupla (tcp_ok, tcp_slow).
        """
        if synthetic.tcp is None:
            return False, False

        tcp = synthetic.tcp

        if not tcp.success:
            return False, False

        if tcp.handshake_time_ms is not None and tcp.handshake_time_ms > TCP_SLOW_THRESHOLD_MS:
            return True, True

        return True, False

    def _check_instability(self, synthetic: SyntheticTestResult) -> bool:
        """
        Verifica se há instabilidade de rede (jitter > 30ms ou perda > 2%).

        Avalia todos os alvos de ping coletados.

        Args:
            synthetic: Resultado dos testes sintéticos.

        Returns:
            True se instabilidade for detectada.
        """
        if synthetic.ping is None:
            return False

        all_stats = []
        if synthetic.ping.gateway:
            all_stats.append(synthetic.ping.gateway)
        all_stats.extend(synthetic.ping.external_targets)

        for stats in all_stats:
            if stats.jitter_ms is not None and stats.jitter_ms > JITTER_THRESHOLD_MS:
                logger.debug(
                    "Instabilidade: jitter=%.1fms em %s (limiar: %.0fms)",
                    stats.jitter_ms, stats.target, JITTER_THRESHOLD_MS,
                )
                return True
            if stats.packet_loss_pct > PACKET_LOSS_THRESHOLD_PCT:
                logger.debug(
                    "Instabilidade: perda=%.1f%% em %s (limiar: %.0f%%)",
                    stats.packet_loss_pct, stats.target, PACKET_LOSS_THRESHOLD_PCT,
                )
                return True

        return False

    # -----------------------------------------------------------------------
    # Nota de saúde (0-100)
    # -----------------------------------------------------------------------

    def _calculate_health_score(
        self,
        verdict: VerdictCode,
        synthetic: Optional[SyntheticTestResult],
    ) -> int:
        """
        Calcula a nota de saúde (0-100) com base no veredito e nas métricas.

        Faixa base por veredito, depois ajustada por métricas numéricas:
            OK                   → 90-100
            NETWORK_INSTABILITY  → 70-89
            FIREWALL_BLOCK       → 50-69
            DNS_FAILURE          → 40-59
            NO_WAN               → 20-39
            L2_ISOLATION         → 0-19
            UNKNOWN              → 0

        Args:
            verdict: Veredito hierárquico calculado.
            synthetic: Dados sintéticos para ajuste fino da nota.

        Returns:
            Nota de saúde inteira entre 0 e 100.
        """
        # Scores base por veredito
        base_scores: dict[VerdictCode, int] = {
            VerdictCode.OK: 95,
            VerdictCode.NETWORK_INSTABILITY: 75,
            VerdictCode.FIREWALL_BLOCK: 55,
            VerdictCode.DNS_FAILURE: 45,
            VerdictCode.NO_WAN: 25,
            VerdictCode.L2_ISOLATION: 10,
            VerdictCode.UNKNOWN: 0,
        }

        score = base_scores.get(verdict, 0)

        if synthetic is None or verdict in (VerdictCode.UNKNOWN, VerdictCode.L2_ISOLATION):
            return score

        # Ajuste fino baseado em métricas numéricas
        penalty = 0.0

        if synthetic.ping:
            all_stats = []
            if synthetic.ping.gateway:
                all_stats.append(synthetic.ping.gateway)
            all_stats.extend(synthetic.ping.external_targets)

            for stats in all_stats:
                # Penalidade por perda de pacotes (até -10 pontos)
                if stats.packet_loss_pct > 0:
                    penalty += min(stats.packet_loss_pct * 0.5, 10.0)

                # Penalidade por jitter elevado (até -10 pontos)
                if stats.jitter_ms and stats.jitter_ms > 10:
                    excess = stats.jitter_ms - 10
                    penalty += min(excess * 0.2, 10.0)

                # Penalidade por latência alta (até -5 pontos)
                if stats.avg_latency_ms and stats.avg_latency_ms > 100:
                    excess = stats.avg_latency_ms - 100
                    penalty += min(excess * 0.02, 5.0)

        if synthetic.dns and synthetic.dns.avg_response_ms:
            if synthetic.dns.avg_response_ms > 100:
                excess = synthetic.dns.avg_response_ms - 100
                penalty += min(excess * 0.01, 5.0)

        if synthetic.tcp and synthetic.tcp.handshake_time_ms:
            if synthetic.tcp.handshake_time_ms > 200:
                excess = synthetic.tcp.handshake_time_ms - 200
                penalty += min(excess * 0.005, 5.0)

        final_score = int(score - penalty)
        return max(0, min(100, final_score))

    @staticmethod
    def _score_to_grade(score: int) -> HealthGrade:
        """
        Converte nota numérica (0-100) para classificação qualitativa.

        Faixas:
            0–39   → CRITICAL
            40–69  → DEGRADED
            70–89  → STABLE
            90–100 → OPTIMAL

        Args:
            score: Nota de saúde de 0 a 100.

        Returns:
            HealthGrade correspondente.
        """
        if score >= 90:
            return HealthGrade.OPTIMAL
        elif score >= 70:
            return HealthGrade.STABLE
        elif score >= 40:
            return HealthGrade.DEGRADED
        else:
            return HealthGrade.CRITICAL

    # -----------------------------------------------------------------------
    # Correlação de eventos passivos com anomalias sintéticas (±30s)
    # -----------------------------------------------------------------------

    def _correlate_events(
        self,
        passive: Optional[PassiveCollectionResult],
        synthetic: Optional[SyntheticTestResult],
    ) -> list[CorrelatedEvent]:
        """
        Correlaciona eventos do Módulo 1 com picos de anomalia do Módulo 2.

        Para cada evento passivo, verifica se ocorreu dentro de ±30s de
        qualquer anomalia detectada nos testes sintéticos.

        Args:
            passive: Resultado da coleta passiva.
            synthetic: Resultado dos testes sintéticos.

        Returns:
            Lista de CorrelatedEvent com eventos causalmente relacionados.
        """
        if not passive or not synthetic:
            return []

        if not passive.events:
            return []

        anomaly_timestamps = self._find_anomaly_timestamps(synthetic)
        if not anomaly_timestamps:
            return []

        correlated: list[CorrelatedEvent] = []
        window = timedelta(seconds=CORRELATION_WINDOW_S)

        for event in passive.events:
            for anomaly_ts, metric_name in anomaly_timestamps:
                delta = abs((event.timestamp - anomaly_ts).total_seconds())
                if delta <= CORRELATION_WINDOW_S:
                    correlated.append(CorrelatedEvent(
                        event=event,
                        related_metric=metric_name,
                        time_delta_s=round(delta, 1),
                    ))
                    logger.debug(
                        "Evento correlacionado: ID=%s ↔ métrica=%s (Δ=%.1fs)",
                        event.event_id, metric_name, delta,
                    )
                    break  # um evento pode correlacionar com uma única métrica

        return correlated

    def _find_anomaly_timestamps(
        self, synthetic: SyntheticTestResult
    ) -> list[tuple[datetime, str]]:
        """
        Extrai os timestamps dos testes sintéticos que apresentaram anomalias.

        Args:
            synthetic: Resultado dos testes sintéticos.

        Returns:
            Lista de tuplas (timestamp_da_anomalia, nome_da_métrica).
        """
        anomalies: list[tuple[datetime, str]] = []
        ts = synthetic.timestamp  # timestamp do ciclo sintético inteiro

        # Anomalias de ping
        if synthetic.ping:
            if synthetic.ping.gateway and synthetic.ping.gateway.packets_received == 0:
                anomalies.append((ts, "ping_gateway_loss_100pct"))

            for stats in synthetic.ping.external_targets:
                if stats.packet_loss_pct >= PACKET_LOSS_THRESHOLD_PCT:
                    anomalies.append((ts, f"ping_loss_{stats.target}"))
                if stats.jitter_ms and stats.jitter_ms >= JITTER_THRESHOLD_MS:
                    anomalies.append((ts, f"jitter_{stats.target}"))

        # Anomalias de DNS
        if synthetic.dns:
            failed = [q for q in synthetic.dns.queries if q.resolved_ip is None]
            if len(failed) == len(synthetic.dns.queries):
                anomalies.append((ts, "dns_all_resolvers_failed"))
            elif synthetic.dns.avg_response_ms and synthetic.dns.avg_response_ms > DNS_SLOW_THRESHOLD_MS:
                anomalies.append((ts, "dns_slow"))

        # Anomalias de TCP
        if synthetic.tcp and (not synthetic.tcp.success or synthetic.tcp.timed_out):
            anomalies.append((ts, "tcp_443_failed"))

        # Anomalias de ARP
        if synthetic.arp:
            if synthetic.arp.arp_incomplete:
                anomalies.append((ts, "arp_incomplete"))
            if synthetic.arp.mac_changed:
                anomalies.append((ts, "arp_mac_changed"))

        return anomalies
