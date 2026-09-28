"""
Módulo 2 — Transações Sintéticas.

Executa testes ativos de conectividade a cada ciclo para medir a saúde
da rede em camadas L2–L7. Todos os testes são assíncronos e possuem timeout.

Testes implementados (Windows + base multiplataforma):
- L2  : Gateway padrão + tabela ARP (detecção de 'incomplete' e mudança de MAC)
- L3  : Ping assíncrono para gateway, 1.1.1.1, 8.8.8.8
- L4/7: DNS raw via socket UDP (sem dnspython — implementação RFC 1035 manual)
- L4  : TCP handshake na porta 443

Dependências: apenas built-ins do Python 3.10+ (asyncio, socket, struct, re, math)
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Optional

from netdiag.models import (
    ArpResult,
    DnsQueryResult,
    DnsResult,
    Platform,
    PingResult,
    PingStats,
    PlatformInfo,
    SyntheticTestResult,
    TcpHandshakeResult,
)

logger = logging.getLogger("netdiag.modules.synthetic_tester")

# ---------------------------------------------------------------------------
# Constantes de configuração
# ---------------------------------------------------------------------------

PING_EXTERNAL_TARGETS: list[str] = ["1.1.1.1", "8.8.8.8"]
DNS_RESOLVERS: list[str] = ["8.8.8.8", "1.1.1.1"]   # + DNS local detectado em runtime
DNS_TEST_HOSTNAME: str = "www.google.com"
TCP_TEST_HOST: str = "www.google.com"
TCP_TEST_PORT: int = 443

PING_COUNT: int = 5
PING_TIMEOUT_S: float = 5.0
DNS_TIMEOUT_S: float = 5.0
TCP_TIMEOUT_S: float = 5.0
SUBPROCESS_TIMEOUT_S: int = 10


class SyntheticTester:
    """
    Executor de transações sintéticas de rede nas camadas L2 a L7.

    Todos os métodos retornam dataclasses com campos `error` para registrar
    falhas sem propagar exceções ao orquestrador.
    """

    def __init__(self, platform: PlatformInfo) -> None:
        """
        Inicializa o testador sintético.

        Args:
            platform: Plataforma detectada para adaptar comandos de SO.
        """
        self.platform = platform
        self._previous_gateway_mac: Optional[str] = None
        self._cached_gateway_ip: Optional[str] = None

    # -----------------------------------------------------------------------
    # API pública
    # -----------------------------------------------------------------------

    async def run_all(self) -> SyntheticTestResult:
        """
        Executa todos os testes sintéticos em paralelo e retorna o resultado consolidado.

        Executa via asyncio.gather para máxima eficiência.
        Falhas em um teste não impedem a execução dos demais.

        Returns:
            SyntheticTestResult com todos os resultados preenchidos.
        """
        timestamp = datetime.now(tz=timezone.utc)

        arp_task = asyncio.create_task(self._safe_check_arp(), name="arp_check")
        ping_task = asyncio.create_task(self._safe_ping_tests(), name="ping_tests")
        dns_task = asyncio.create_task(self._safe_dns_tests(), name="dns_tests")
        tcp_task = asyncio.create_task(self._safe_tcp_test(), name="tcp_test")

        arp_result, ping_result, dns_result, tcp_result = await asyncio.gather(
            arp_task, ping_task, dns_task, tcp_task,
        )

        return SyntheticTestResult(
            timestamp=timestamp,
            arp=arp_result,
            ping=ping_result,
            dns=dns_result,
            tcp=tcp_result,
        )

    # -----------------------------------------------------------------------
    # Wrappers seguros (capturam exceções)
    # -----------------------------------------------------------------------

    async def _safe_check_arp(self) -> ArpResult:
        """Wrapper com captura de exceção para check_arp."""
        try:
            return await self.check_arp()
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro no teste ARP: %s", exc, exc_info=True)
            return ArpResult(
                timestamp=datetime.now(tz=timezone.utc),
                gateway_ip=None, gateway_mac=None,
                error=str(exc),
            )

    async def _safe_ping_tests(self) -> PingResult:
        """Wrapper com captura de exceção para run_ping_tests."""
        try:
            return await self.run_ping_tests()
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro nos testes de ping: %s", exc, exc_info=True)
            return PingResult(
                timestamp=datetime.now(tz=timezone.utc),
                gateway=None, external_targets=[],
            )

    async def _safe_dns_tests(self) -> DnsResult:
        """Wrapper com captura de exceção para run_dns_tests."""
        try:
            return await self.run_dns_tests()
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro nos testes DNS: %s", exc, exc_info=True)
            return DnsResult(timestamp=datetime.now(tz=timezone.utc))

    async def _safe_tcp_test(self) -> TcpHandshakeResult:
        """Wrapper com captura de exceção para run_tcp_test."""
        try:
            return await self.run_tcp_test()
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro no teste TCP: %s", exc, exc_info=True)
            return TcpHandshakeResult(
                timestamp=datetime.now(tz=timezone.utc),
                target_host=TCP_TEST_HOST, target_ip=None,
                error=str(exc),
            )

    # -----------------------------------------------------------------------
    # L2 — ARP / Gateway
    # -----------------------------------------------------------------------

    async def check_arp(self) -> ArpResult:
        """
        Verifica a tabela ARP para detectar o MAC do gateway padrão.

        Detecta:
        - Entrada ARP marcada como 'incomplete'/'incompleto'.
        - Mudança de MAC do gateway em relação ao ciclo anterior.

        Returns:
            ArpResult com gateway_ip, gateway_mac e flags de anomalia.
        """
        timestamp = datetime.now(tz=timezone.utc)
        errors: list[str] = []

        gateway_ip = await self._get_default_gateway()
        self._cached_gateway_ip = gateway_ip

        if gateway_ip is None:
            return ArpResult(
                timestamp=timestamp,
                gateway_ip=None,
                gateway_mac=None,
                error="Não foi possível detectar o gateway padrão",
            )

        # Obter tabela ARP completa para log bruto
        arp_raw = await self._run_subprocess(
            ["arp", "-a"], errors=errors
        ) or ""

        gateway_mac, is_incomplete = await self._get_mac_from_arp(gateway_ip, arp_raw)

        mac_changed = False
        if (
            gateway_mac is not None
            and self._previous_gateway_mac is not None
            and gateway_mac.lower() != self._previous_gateway_mac.lower()
        ):
            mac_changed = True
            logger.warning(
                "MAC do gateway mudou! Anterior: %s → Atual: %s (possível ARP spoofing)",
                self._previous_gateway_mac,
                gateway_mac,
            )

        if gateway_mac is not None:
            self._previous_gateway_mac = gateway_mac

        error_msg = "; ".join(errors) if errors else None

        return ArpResult(
            timestamp=timestamp,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            mac_changed=mac_changed,
            arp_incomplete=is_incomplete,
            raw_arp_table=arp_raw,
            error=error_msg,
        )

    async def _get_default_gateway(self) -> Optional[str]:
        """
        Detecta o IP do gateway padrão usando o comando apropriado para o SO.

        Windows: parse de `route print 0.0.0.0` (mais confiável que ipconfig).
        macOS  : parse de `route -n get default`.

        Returns:
            IP do gateway como string, ou None se não detectado.
        """
        if self.platform.name == Platform.WINDOWS:
            return await self._get_gateway_windows()
        else:
            return await self._get_gateway_macos()

    async def _get_gateway_windows(self) -> Optional[str]:
        """
        Obtém o gateway padrão no Windows via `route print 0.0.0.0`.

        Parseia a saída buscando a linha com destino 0.0.0.0 e máscara 0.0.0.0.

        Returns:
            IP do gateway ou None.
        """
        raw = await self._run_subprocess(["route", "print", "0.0.0.0"])
        if not raw:
            # Fallback: ipconfig
            return await self._get_gateway_windows_ipconfig()

        # Padrão da linha: "         0.0.0.0          0.0.0.0    192.168.1.1    192.168.1.100   ..."
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                candidate = parts[2]
                if _is_valid_ipv4(candidate):
                    logger.debug("Gateway detectado (route print): %s", candidate)
                    return candidate

        return await self._get_gateway_windows_ipconfig()

    async def _get_gateway_windows_ipconfig(self) -> Optional[str]:
        """
        Fallback: obtém o gateway padrão via `ipconfig`.

        Returns:
            IP do gateway ou None.
        """
        raw = await self._run_subprocess(["ipconfig"])
        if not raw:
            return None

        # Procura "Gateway Padrão" ou "Default Gateway"
        for line in raw.splitlines():
            lower = line.lower()
            if "gateway padrão" in lower or "default gateway" in lower:
                match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if match:
                    return match.group(1)
        return None

    async def _get_gateway_macos(self) -> Optional[str]:
        """
        Obtém o gateway padrão no macOS via `route -n get default`.

        Returns:
            IP do gateway ou None.
        """
        raw = await self._run_subprocess(["route", "-n", "get", "default"])
        if not raw:
            return None

        for line in raw.splitlines():
            if "gateway:" in line.lower():
                match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if match:
                    return match.group(1)
        return None

    async def _get_mac_from_arp(
        self, ip: str, arp_raw: str
    ) -> tuple[Optional[str], bool]:
        """
        Retorna o MAC address e flag de 'incomplete' para um IP na tabela ARP.

        Args:
            ip: IP a ser consultado.
            arp_raw: Saída bruta de `arp -a` já coletada.

        Returns:
            Tupla (mac_address ou None, is_incomplete: bool).
        """
        if not arp_raw:
            return None, False

        ip_escaped = re.escape(ip)
        is_incomplete = False

        for line in arp_raw.splitlines():
            if ip in line:
                # Detectar 'incomplete' / 'incompleto' (Windows PT-BR)
                if re.search(r"\bincomplete\b|\bincompleto\b", line, re.IGNORECASE):
                    is_incomplete = True
                    return None, True

                # Extrair MAC: formatos aa-bb-cc-dd-ee-ff (Windows) ou aa:bb:cc:dd:ee:ff (macOS)
                mac_match = re.search(
                    r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                    r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})",
                    line,
                )
                if mac_match:
                    mac = mac_match.group(1).replace("-", ":").lower()
                    return mac, False

        return None, False

    # -----------------------------------------------------------------------
    # L3 — Ping assíncrono
    # -----------------------------------------------------------------------

    async def run_ping_tests(self) -> PingResult:
        """
        Executa pings assíncronos para o gateway e para os alvos externos.

        Usa `asyncio.create_subprocess_exec` — NUNCA subprocess.run bloqueante.
        Calcula latência média, mínima, máxima e jitter (desvio padrão).

        Returns:
            PingResult com PingStats para o gateway e cada alvo externo.
        """
        timestamp = datetime.now(tz=timezone.utc)

        # Gateway: usar o valor já detectado pelo check_arp ou detectar agora
        gateway_ip = self._cached_gateway_ip or await self._get_default_gateway()

        tasks = []
        labels: list[Optional[str]] = []

        if gateway_ip:
            tasks.append(asyncio.create_task(
                self._ping_target(gateway_ip, count=PING_COUNT),
                name=f"ping_{gateway_ip}",
            ))
            labels.append("gateway")
        else:
            labels.append(None)

        for target in PING_EXTERNAL_TARGETS:
            tasks.append(asyncio.create_task(
                self._ping_target(target, count=PING_COUNT),
                name=f"ping_{target}",
            ))
            labels.append(target)

        results = await asyncio.gather(*tasks)

        gateway_stats: Optional[PingStats] = None
        external_stats: list[PingStats] = []

        result_iter = iter(results)
        if gateway_ip:
            gateway_stats = next(result_iter)
        else:
            gateway_stats = PingStats(
                target="gateway",
                error="Gateway não detectado — ping ignorado",
            )

        for stats in result_iter:
            external_stats.append(stats)

        return PingResult(
            timestamp=timestamp,
            gateway=gateway_stats,
            external_targets=external_stats,
        )

    async def _ping_target(self, target: str, count: int = PING_COUNT) -> PingStats:
        """
        Executa ping para um único alvo e calcula estatísticas.

        Args:
            target: IP ou hostname do alvo.
            count: Número de pacotes a enviar.

        Returns:
            PingStats com latências e percentual de perda.
        """
        if self.platform.name == Platform.WINDOWS:
            cmd = ["ping", "-n", str(count), "-w", "3000", target]
        else:
            cmd = ["ping", "-c", str(count), "-W", "3", target]

        raw, _ = await self._run_subprocess_with_stderr(cmd, timeout=int(PING_TIMEOUT_S) + count * 3)

        if raw is None:
            return PingStats(
                target=target,
                packets_sent=count,
                packet_loss_pct=100.0,
                error=f"Comando ping falhou para {target}",
            )

        return self._parse_ping_output(raw, target)

    @staticmethod
    def _calculate_jitter(latencies: list[float]) -> Optional[float]:
        """
        Calcula o jitter como desvio padrão das latências.

        Args:
            latencies: Lista de latências em milissegundos.

        Returns:
            Desvio padrão em ms com 2 casas decimais, ou None se < 2 elementos.
        """
        if len(latencies) < 2:
            return None
        n = len(latencies)
        mean = sum(latencies) / n
        variance = sum((x - mean) ** 2 for x in latencies) / (n - 1)
        return round(math.sqrt(variance), 2)

    @staticmethod
    def _parse_ping_output(raw: str, target: str) -> PingStats:
        """
        Faz o parse da saída do comando ping (Windows e macOS/Linux).

        Windows: "Mínimo = Xms, Máximo = Yms, Média = Zms"
                 "Pacotes: Enviados = N, Recebidos = M, Perdidos = P"
        macOS  : "rtt min/avg/max/mdev = X/Y/Z/W ms"
                 "N packets transmitted, M received, P% packet loss"

        Args:
            raw: Saída bruta do comando ping.
            target: IP/hostname alvo.

        Returns:
            PingStats preenchido.
        """
        latencies: list[float] = []
        packets_sent = 0
        packets_received = 0
        packet_loss_pct = 0.0

        # ---------------------------------------------------------------
        # Windows — extrair latências individuais de cada linha de resposta
        # ---------------------------------------------------------------
        # Linha típica PT-BR: "Resposta de 8.8.8.8: bytes=32 tempo=15ms TTL=57"
        # Linha EN: "Reply from 8.8.8.8: bytes=32 time=15ms TTL=57"
        for line in raw.splitlines():
            m = re.search(r"tempo[<=](\d+)ms|time[<=](\d+)ms", line, re.IGNORECASE)
            if m:
                val = m.group(1) or m.group(2)
                latencies.append(float(val))

        # macOS/Linux — "64 bytes from ... icmp_seq=1 ttl=57 time=12.3 ms"
        if not latencies:
            for line in raw.splitlines():
                m = re.search(r"time=(\d+\.?\d*)\s*ms", line, re.IGNORECASE)
                if m:
                    latencies.append(float(m.group(1)))

        # ---------------------------------------------------------------
        # Windows — estatísticas de pacotes
        # PT-BR: "Pacotes: Enviados = 4, Recebidos = 4, Perdidos = 0 (0% de perda)"
        # EN    : "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        # ---------------------------------------------------------------
        for line in raw.splitlines():
            m_sent = re.search(r"enviados\s*=\s*(\d+)|sent\s*=\s*(\d+)", line, re.IGNORECASE)
            m_recv = re.search(r"recebidos\s*=\s*(\d+)|received\s*=\s*(\d+)", line, re.IGNORECASE)
            m_loss = re.search(r"(\d+)%\s*(?:de perda|loss)", line, re.IGNORECASE)

            if m_sent:
                packets_sent = int(m_sent.group(1) or m_sent.group(2))
            if m_recv:
                packets_received = int(m_recv.group(1) or m_recv.group(2))
            if m_loss:
                packet_loss_pct = float(m_loss.group(1))

        # macOS/Linux: "4 packets transmitted, 4 received, 0% packet loss"
        if packets_sent == 0:
            m = re.search(r"(\d+) packets? transmitted,\s*(\d+) received", raw, re.IGNORECASE)
            if m:
                packets_sent = int(m.group(1))
                packets_received = int(m.group(2))
                m_loss = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", raw, re.IGNORECASE)
                if m_loss:
                    packet_loss_pct = float(m_loss.group(1))
                elif packets_sent > 0:
                    packet_loss_pct = (packets_sent - packets_received) / packets_sent * 100

        # Calcular estatísticas a partir das latências individuais coletadas
        avg_ms: Optional[float] = None
        min_ms: Optional[float] = None
        max_ms: Optional[float] = None
        jitter: Optional[float] = None

        if latencies:
            avg_ms = round(sum(latencies) / len(latencies), 2)
            min_ms = round(min(latencies), 2)
            max_ms = round(max(latencies), 2)
            jitter = SyntheticTester._calculate_jitter(latencies)

            # Recalcular perda se não parseou do texto
            if packets_sent == 0 and latencies:
                packets_sent = PING_COUNT
                packets_received = len(latencies)
                packet_loss_pct = round(
                    (packets_sent - packets_received) / packets_sent * 100, 1
                )

        return PingStats(
            target=target,
            packets_sent=packets_sent,
            packets_received=packets_received,
            packet_loss_pct=packet_loss_pct,
            latencies_ms=latencies,
            avg_latency_ms=avg_ms,
            min_latency_ms=min_ms,
            max_latency_ms=max_ms,
            jitter_ms=jitter,
        )

    # -----------------------------------------------------------------------
    # L4/7 — DNS raw via socket UDP (RFC 1035 simplificado)
    # -----------------------------------------------------------------------

    async def run_dns_tests(self) -> DnsResult:
        """
        Executa consultas DNS raw em múltiplos resolvers para medir latência real.

        NÃO usa `socket.gethostbyname` (mede cache do SO, não o resolver).
        Implementação manual do protocolo DNS sobre UDP (RFC 1035 simplificado).

        Resolvers testados: 8.8.8.8, 1.1.1.1, + DNS local do sistema.

        Returns:
            DnsResult com uma DnsQueryResult por resolver, e o mais rápido identificado.
        """
        timestamp = datetime.now(tz=timezone.utc)

        resolvers = list(DNS_RESOLVERS)

        # Tentar adicionar o DNS local do sistema
        local_dns = await self._get_system_dns_resolver()
        if local_dns and local_dns not in resolvers:
            resolvers.append(local_dns)

        tasks = [
            asyncio.create_task(
                self._query_dns_raw(resolver, DNS_TEST_HOSTNAME),
                name=f"dns_{resolver}",
            )
            for resolver in resolvers
        ]

        queries: list[DnsQueryResult] = await asyncio.gather(*tasks)

        # Identificar o resolver mais rápido (que não teve erro)
        successful = [q for q in queries if q.resolved_ip and q.response_time_ms is not None]
        fastest_resolver = None
        avg_ms = None

        if successful:
            fastest = min(successful, key=lambda q: q.response_time_ms)  # type: ignore
            fastest_resolver = fastest.resolver_ip
            avg_ms = round(
                sum(q.response_time_ms for q in successful) / len(successful), 2  # type: ignore
            )

        return DnsResult(
            timestamp=timestamp,
            queries=queries,
            fastest_resolver_ip=fastest_resolver,
            avg_response_ms=avg_ms,
        )

    async def _query_dns_raw(
        self,
        resolver_ip: str,
        hostname: str,
        timeout: float = DNS_TIMEOUT_S,
    ) -> DnsQueryResult:
        """
        Realiza uma consulta DNS tipo A via socket UDP raw (RFC 1035).

        Constrói o pacote DNS manualmente sem dnspython.
        Mede o RTT entre envio e recebimento da resposta.

        Args:
            resolver_ip: IP do servidor DNS a consultar.
            hostname: Nome de domínio a resolver.
            timeout: Timeout em segundos.

        Returns:
            DnsQueryResult com IP resolvido e tempo de resposta.
        """
        query_packet = self._build_dns_query(hostname)

        loop = asyncio.get_event_loop()

        def _do_dns_query() -> tuple[Optional[str], float]:
            """Executa a query DNS num executor de thread (socket bloqueante)."""
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                t_start = time.perf_counter()
                sock.sendto(query_packet, (resolver_ip, 53))
                data, _ = sock.recvfrom(512)
                t_end = time.perf_counter()
                elapsed_ms = round((t_end - t_start) * 1000, 2)
                resolved = self._parse_dns_response(data)
                return resolved, elapsed_ms
            finally:
                sock.close()

        try:
            resolved_ip, elapsed_ms = await asyncio.wait_for(
                loop.run_in_executor(None, _do_dns_query),
                timeout=timeout + 1.0,
            )

            if resolved_ip is None:
                return DnsQueryResult(
                    resolver_ip=resolver_ip,
                    queried_hostname=hostname,
                    resolved_ip=None,
                    response_time_ms=elapsed_ms,
                    error="NXDOMAIN ou resposta vazia",
                )

            return DnsQueryResult(
                resolver_ip=resolver_ip,
                queried_hostname=hostname,
                resolved_ip=resolved_ip,
                response_time_ms=elapsed_ms,
            )

        except asyncio.TimeoutError:
            return DnsQueryResult(
                resolver_ip=resolver_ip,
                queried_hostname=hostname,
                resolved_ip=None,
                response_time_ms=None,
                timed_out=True,
                error=f"Timeout ({timeout}s) ao consultar {resolver_ip}",
            )
        except OSError as exc:
            return DnsQueryResult(
                resolver_ip=resolver_ip,
                queried_hostname=hostname,
                resolved_ip=None,
                response_time_ms=None,
                error=f"Erro de socket ao consultar {resolver_ip}: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            return DnsQueryResult(
                resolver_ip=resolver_ip,
                queried_hostname=hostname,
                resolved_ip=None,
                response_time_ms=None,
                error=f"Erro inesperado: {exc}",
            )

    @staticmethod
    def _build_dns_query(hostname: str, query_id: int = 0x1A2B) -> bytes:
        """
        Constrói um pacote de consulta DNS tipo A no formato de wire (RFC 1035).

        Formato do header DNS (12 bytes):
            ID       (2B): identificador da consulta
            Flags    (2B): 0x0100 = query padrão, recursão desejada
            QDCOUNT  (2B): 1 (uma pergunta)
            ANCOUNT  (2B): 0
            NSCOUNT  (2B): 0
            ARCOUNT  (2B): 0

        QNAME: sequência de labels length-prefixed, terminada por 0x00.
        QTYPE : 0x0001 (A record)
        QCLASS: 0x0001 (IN — Internet)

        Args:
            hostname: Nome de domínio (ex: 'www.google.com').
            query_id: ID da consulta para correlacionar resposta.

        Returns:
            Bytes do pacote DNS pronto para envio via socket UDP.
        """
        # Header
        header = struct.pack(
            ">HHHHHH",
            query_id,   # ID
            0x0100,     # Flags: QR=0 (query), Opcode=0, RD=1 (recursion desired)
            1,          # QDCOUNT
            0,          # ANCOUNT
            0,          # NSCOUNT
            0,          # ARCOUNT
        )

        # QNAME: cada label é prefixado com seu comprimento em bytes
        qname = b""
        for label in hostname.rstrip(".").split("."):
            encoded = label.encode("ascii")
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"  # terminator

        # QTYPE=A (1), QCLASS=IN (1)
        question = qname + struct.pack(">HH", 1, 1)

        return header + question

    @staticmethod
    def _parse_dns_response(data: bytes) -> Optional[str]:
        """
        Extrai o primeiro endereço IPv4 de uma resposta DNS tipo A.

        Pula o header (12 bytes) e a seção de perguntas, depois itera
        sobre os registros de resposta para encontrar o primeiro tipo A (0x0001).

        Args:
            data: Bytes brutos da resposta DNS.

        Returns:
            IP como string (ex: '142.250.80.36'), ou None em caso de falha/NXDOMAIN.
        """
        if len(data) < 12:
            return None

        try:
            # Header
            _id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])

            # Verificar RCODE (4 bits menos significativos de flags)
            rcode = flags & 0x000F
            if rcode != 0:
                return None  # NXDOMAIN (3), SERVFAIL (2), etc.

            if ancount == 0:
                return None

            offset = 12

            # Pular a seção de perguntas (QDCOUNT)
            for _ in range(qdcount):
                offset = _skip_dns_name(data, offset)
                offset += 4  # QTYPE (2B) + QCLASS (2B)

            # Iterar sobre respostas
            for _ in range(ancount):
                offset = _skip_dns_name(data, offset)

                if offset + 10 > len(data):
                    break

                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10

                if rtype == 1 and rdlength == 4:  # Tipo A, IPv4
                    ip_bytes = data[offset:offset + 4]
                    return ".".join(str(b) for b in ip_bytes)

                offset += rdlength

        except (struct.error, IndexError):
            pass

        return None

    async def _get_system_dns_resolver(self) -> Optional[str]:
        """
        Detecta o IP do resolver DNS configurado no sistema.

        Windows: `ipconfig /all` — campo 'Servidores DNS' / 'DNS Servers'.
        macOS  : `/etc/resolv.conf` ou `scutil --dns`.

        Returns:
            IP do primeiro resolver DNS do sistema, ou None.
        """
        if self.platform.name == Platform.WINDOWS:
            return await self._get_dns_windows()
        else:
            return await self._get_dns_macos()

    async def _get_dns_windows(self) -> Optional[str]:
        """Detecta o DNS do sistema no Windows via `ipconfig /all`."""
        raw = await self._run_subprocess(["ipconfig", "/all"])
        if not raw:
            return None

        for line in raw.splitlines():
            lower = line.lower()
            if "servidores dns" in lower or "dns servers" in lower:
                match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if match:
                    ip = match.group(1)
                    # Ignorar loopback e endereços inválidos
                    if not ip.startswith("127.") and ip != "0.0.0.0":
                        return ip
        return None

    async def _get_dns_macos(self) -> Optional[str]:
        """Detecta o DNS do sistema no macOS via /etc/resolv.conf."""
        try:
            import pathlib
            resolv = pathlib.Path("/etc/resolv.conf")
            if resolv.exists():
                for line in resolv.read_text().splitlines():
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2 and _is_valid_ipv4(parts[1]):
                            return parts[1]
        except Exception:  # noqa: BLE001
            pass
        return None

    # -----------------------------------------------------------------------
    # L4 — TCP Handshake
    # -----------------------------------------------------------------------

    async def run_tcp_test(self) -> TcpHandshakeResult:
        """
        Mede o tempo de handshake TCP na porta 443 de TCP_TEST_HOST.

        Usa `asyncio.open_connection` com timeout. Fecha imediatamente
        após o handshake (sem enviar dados TLS/HTTP).

        Returns:
            TcpHandshakeResult com tempo do handshake e flag de sucesso.
        """
        timestamp = datetime.now(tz=timezone.utc)

        # Primeiro resolve o hostname via DNS raw para obter o IP real
        dns_result = await self._query_dns_raw("8.8.8.8", TCP_TEST_HOST)
        target_ip = dns_result.resolved_ip

        if target_ip is None:
            # Fallback: usar socket.getaddrinfo (pode ser cache do SO)
            try:
                infos = socket.getaddrinfo(TCP_TEST_HOST, TCP_TEST_PORT, socket.AF_INET)
                if infos:
                    target_ip = infos[0][4][0]
            except Exception:  # noqa: BLE001
                pass

        if target_ip is None:
            return TcpHandshakeResult(
                timestamp=timestamp,
                target_host=TCP_TEST_HOST,
                target_ip=None,
                port=TCP_TEST_PORT,
                error=f"Não foi possível resolver {TCP_TEST_HOST} para teste TCP",
            )

        t_start = time.perf_counter()
        writer: Optional[asyncio.StreamWriter] = None

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, TCP_TEST_PORT),
                timeout=TCP_TIMEOUT_S,
            )
            t_end = time.perf_counter()
            elapsed_ms = round((t_end - t_start) * 1000, 2)

            return TcpHandshakeResult(
                timestamp=timestamp,
                target_host=TCP_TEST_HOST,
                target_ip=target_ip,
                port=TCP_TEST_PORT,
                handshake_time_ms=elapsed_ms,
                success=True,
            )

        except asyncio.TimeoutError:
            return TcpHandshakeResult(
                timestamp=timestamp,
                target_host=TCP_TEST_HOST,
                target_ip=target_ip,
                port=TCP_TEST_PORT,
                success=False,
                timed_out=True,
                error=f"Timeout ({TCP_TIMEOUT_S}s) no handshake TCP com {target_ip}:{TCP_TEST_PORT}",
            )
        except OSError as exc:
            return TcpHandshakeResult(
                timestamp=timestamp,
                target_host=TCP_TEST_HOST,
                target_ip=target_ip,
                port=TCP_TEST_PORT,
                success=False,
                error=f"Erro de conexão TCP: {exc}",
            )
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass

    # -----------------------------------------------------------------------
    # Utilitários de subprocess assíncrono
    # -----------------------------------------------------------------------

    async def _run_subprocess(
        self,
        cmd: list[str],
        timeout: int = SUBPROCESS_TIMEOUT_S,
        errors: Optional[list[str]] = None,
    ) -> Optional[str]:
        """
        Executa um subprocesso assíncrono com timeout, retornando apenas stdout.

        Args:
            cmd: Lista com o comando e argumentos.
            timeout: Timeout máximo em segundos.
            errors: Lista mutável onde mensagens de erro são acrescentadas.

        Returns:
            stdout como string, ou None em caso de falha.
        """
        stdout, _ = await self._run_subprocess_with_stderr(cmd, timeout, errors)
        return stdout

    async def _run_subprocess_with_stderr(
        self,
        cmd: list[str],
        timeout: int = SUBPROCESS_TIMEOUT_S,
        errors: Optional[list[str]] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Executa um subprocesso assíncrono com timeout, retornando stdout e stderr.

        Args:
            cmd: Lista com o comando e argumentos.
            timeout: Timeout máximo em segundos.
            errors: Lista mutável onde mensagens de erro são acrescentadas.

        Returns:
            Tupla (stdout, stderr) como strings, ou (None, msg_erro).
        """
        cmd_str = " ".join(cmd)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout)
            )
            stdout = stdout_b.decode("utf-8", errors="replace").strip()
            stderr = stderr_b.decode("utf-8", errors="replace").strip()
            return stdout or None, stderr or None

        except asyncio.TimeoutError:
            msg = f"Timeout ({timeout}s): '{cmd_str}'"
            logger.warning(msg)
            if errors is not None:
                errors.append(msg)
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
            return None, msg

        except FileNotFoundError:
            msg = f"Comando não encontrado: '{cmd[0]}'"
            logger.warning(msg)
            if errors is not None:
                errors.append(msg)
            return None, msg

        except Exception as exc:  # noqa: BLE001
            msg = f"Erro inesperado em '{cmd_str}': {exc}"
            logger.error(msg)
            if errors is not None:
                errors.append(msg)
            return None, msg


# ---------------------------------------------------------------------------
# Funções auxiliares de nível de módulo
# ---------------------------------------------------------------------------

def _is_valid_ipv4(ip: str) -> bool:
    """
    Valida se uma string é um endereço IPv4 bem formado.

    Args:
        ip: String a validar.

    Returns:
        True se for IPv4 válido.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _skip_dns_name(data: bytes, offset: int) -> int:
    """
    Avança o offset além de um QNAME no wire format DNS, suportando compressão.

    Args:
        data: Buffer completo da resposta DNS.
        offset: Posição inicial do nome.

    Returns:
        Novo offset logo após o nome.
    """
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            # Ponteiro de compressão (2 bytes)
            return offset + 2
        offset += 1 + length
    return offset
