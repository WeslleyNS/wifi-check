"""
Dataclasses e enums compartilhados por todos os módulos do NetDiag Agent.

Estas estruturas são os contratos de dados entre o Módulo 1 (coleta passiva),
Módulo 2 (transações sintéticas) e Módulo 3 (motor de decisão).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Platform(enum.Enum):
    """Sistema operacional detectado."""
    WINDOWS = "windows"
    MACOS = "macos"
    UNSUPPORTED = "unsupported"


class HealthGrade(enum.Enum):
    """
    Classificação qualitativa da saúde da rede, derivada da nota numérica.

    Mapeamento orientativo:
        CRITICAL  : 0–39
        DEGRADED  : 40–69
        STABLE    : 70–89
        OPTIMAL   : 90–100
    """
    CRITICAL = "crítica"
    DEGRADED = "degradada"
    STABLE = "estável"
    OPTIMAL = "ótima"


class VerdictCode(enum.Enum):
    """
    Códigos de veredito hierárquico gerados pelo Módulo 3.

    A hierarquia segue a ordem de avaliação (da camada 2 para cima).
    """
    OK = "OK"
    L2_ISOLATION = "L2_ISOLATION"          # Ping gateway falhou → isolamento L2
    NO_WAN = "NO_WAN"                       # Gateway OK, externo falhou → sem WAN
    DNS_FAILURE = "DNS_FAILURE"             # Pings OK, DNS > 500ms ou falhou
    FIREWALL_BLOCK = "FIREWALL_BLOCK"       # DNS OK, TCP 443 falhou ou > 1s
    NETWORK_INSTABILITY = "NETWORK_INSTABILITY"  # Jitter > 30ms ou perda > 2%
    UNKNOWN = "UNKNOWN"                     # Não foi possível determinar


class DisconnectCause(enum.Enum):
    """
    Causa identificada de uma desconexão Wi-Fi.

    Derivada da análise dos Event IDs 8001, 8002, 8003 do Windows
    WLAN-AutoConfig e do campo Reason/ReasonCode de cada evento.
    """
    USER_INITIATED    = "Máquina iniciou a desconexão"
    AP_KICKED         = "Ponto de acesso desconectou a máquina"
    SIGNAL_LOSS       = "Perda de sinal / timeout de associação"
    AUTH_FAILURE      = "Falha de autenticação"
    ROAMING           = "Roaming para outro ponto de acesso"
    DRIVER_RESET      = "Reset do driver ou adaptador Wi-Fi"
    SLEEP_HIBERNATE   = "Suspensão ou hibernação do sistema"
    DEAUTH_INACTIVITY = "Desautenticação por inatividade (AP)"
    UNKNOWN           = "Causa desconhecida"


# ---------------------------------------------------------------------------
# Dataclasses de plataforma e privilégio
# ---------------------------------------------------------------------------

@dataclass
class PlatformInfo:
    """Informações sobre a plataforma de execução."""
    name: Platform
    """Plataforma detectada (WINDOWS, MACOS, etc.)."""

    os_version: str
    """Versão do SO como string legível (ex: 'Windows 11 22H2', 'macOS 14.4')."""

    architecture: str
    """Arquitetura da CPU (ex: 'x86_64', 'arm64')."""


@dataclass
class PrivilegeInfo:
    """Estado de privilégios do processo em execução."""
    is_elevated: bool
    """True se o processo possui privilégios elevados (Admin no Windows, root no macOS)."""

    skipped_collections: list[str] = field(default_factory=list)
    """Lista de coletas que serão ignoradas por falta de privilégio."""


# ---------------------------------------------------------------------------
# Módulo 1 — Coleta Passiva
# ---------------------------------------------------------------------------

@dataclass
class WifiInterfaceState:
    """Estado atual da interface Wi-Fi, coletado de forma passiva."""
    timestamp: datetime
    """Momento da coleta."""

    ssid: Optional[str]
    """Nome da rede conectada (None se desconectado)."""

    bssid: Optional[str]
    """MAC do ponto de acesso (None se desconectado)."""

    rssi_dbm: Optional[int]
    """Potência do sinal em dBm (None se não disponível)."""

    channel: Optional[int]
    """Canal Wi-Fi em uso (None se não disponível)."""

    band: Optional[str]
    """Banda de frequência (ex: '2.4 GHz', '5 GHz', '6 GHz')."""

    auth_type: Optional[str]
    """Tipo de autenticação (ex: 'WPA2-Personal', 'WPA3')."""

    interface_name: Optional[str]
    """Nome da interface de rede (ex: 'Wi-Fi', 'en0')."""

    raw_output: str = ""
    """Saída bruta do comando que gerou este estado."""

    collection_method: str = "unknown"
    """Método usado para coletar: 'netsh', 'wdutil', 'system_profiler', etc."""

    error: Optional[str] = None
    """Mensagem de erro, se a coleta falhou parcial ou totalmente."""


@dataclass
class WifiEvent:
    """Evento de rede parseado a partir dos logs do sistema operacional."""
    timestamp: datetime
    """Momento em que o evento ocorreu (extraído do log, não da coleta)."""

    event_id: Optional[str]
    """Identificador do evento (ex: '8001', '8003' no Windows; categoria no macOS)."""

    description: str
    """Descrição legível do evento."""

    raw_data: str = ""
    """XML ou texto bruto do evento."""

    severity: str = "info"
    """Severidade: 'info', 'warning', 'error'."""


@dataclass
class DisconnectRecord:
    """
    Registro detalhado de uma desconexão Wi-Fi, com causa identificada
    e explicação em PT-BR.

    Construído a partir da análise cruzada de Event IDs 8001 (conexão),
    8002 (falha de conexão) e 8003 (desconexão) do log WLAN-AutoConfig.
    """
    timestamp: datetime
    """Horário da desconexão (de Event 8003)."""

    ssid: Optional[str]
    """Nome da rede (SSID) que estava conectada."""

    bssid: Optional[str]
    """MAC do ponto de acesso que estava em uso."""

    cause: DisconnectCause
    """Causa classificada da desconexão."""

    cause_explanation: str
    """Explicação detalhada em PT-BR do que aconteceu e possíveis motivos."""

    raw_reason: str
    """Texto bruto do campo Reason/ReasonCode extraído do evento."""

    reconnected_at: Optional[datetime] = None
    """Timestamp do Event 8001 seguinte (reconexão). None se não reconectou."""

    downtime_seconds: Optional[float] = None
    """Segundos até reconectar. None se não reconectou dentro do período observado."""

    reconnected_ssid: Optional[str] = None
    """SSID ao qual reconectou (pode diferir em casos de roaming)."""

    event_id: str = "8003"
    severity: str = "warning"


@dataclass
class DriverInfo:
    """
    Informações sobre o driver do adaptador Wi-Fi da máquina.

    Coletado via `netsh wlan show drivers` (Windows) ou
    `system_profiler SPAirPortDataType` (macOS).
    Verifica se o driver está desatualizado com base na data de lançamento.
    """
    adapter_name: Optional[str] = None
    """Nome do adaptador Wi-Fi (ex: 'Intel(R) Wi-Fi 6E AX211 160MHz')."""

    provider: Optional[str] = None
    """Fabricante do driver (ex: 'Intel Corporation')."""

    version: Optional[str] = None
    """Versão do driver (ex: '22.230.0.5')."""

    date_str: Optional[str] = None
    """Data do driver como string original (ex: '7/12/2023', '2023-07-12')."""

    date_parsed: Optional[datetime] = None
    """Data do driver parseada para datetime (UTC). None se não foi possível parsear."""

    age_days: Optional[int] = None
    """Idade do driver em dias a partir da data de hoje."""

    is_outdated: Optional[bool] = None
    """True se o driver tem mais de 730 dias (~2 anos). None se não foi possível calcular."""

    inf_file: Optional[str] = None
    """Nome do arquivo INF do driver (Windows apenas)."""

    collection_method: str = "unknown"
    """Método de coleta: 'netsh_drivers' (Windows) ou 'system_profiler' (macOS)."""

    error: Optional[str] = None
    """Mensagem de erro, se a coleta falhou."""


@dataclass
class PassiveCollectionResult:
    """Resultado completo de um ciclo do Módulo 1 (coleta passiva)."""
    timestamp: datetime
    """Momento de início da coleta."""

    interface_state: Optional[WifiInterfaceState]
    """Estado atual da interface Wi-Fi."""

    events: list[WifiEvent] = field(default_factory=list)
    """Eventos de rede coletados no período."""

    disconnect_history: list[DisconnectRecord] = field(default_factory=list)
    """
    Histórico de desconexões com causa identificada.
    Ordenado do mais recente para o mais antigo.
    """

    driver_info: Optional[DriverInfo] = None
    """Informações do driver do adaptador Wi-Fi (versão, data, status de atualização)."""

    events_source: str = "unknown"
    """Fonte dos eventos: 'wevtutil', 'powershell', 'sem_acesso', 'vazio'."""

    errors: list[str] = field(default_factory=list)
    """Erros não-fatais ocorridos durante a coleta."""


# ---------------------------------------------------------------------------
# Módulo 2 — Transações Sintéticas
# ---------------------------------------------------------------------------

@dataclass
class ArpResult:
    """Resultado da verificação da tabela ARP (Camada 2)."""
    timestamp: datetime

    gateway_ip: Optional[str]
    """IP do gateway padrão detectado."""

    gateway_mac: Optional[str]
    """MAC do gateway na tabela ARP (None se 'incomplete'/'incompleto')."""

    mac_changed: bool = False
    """True se o MAC do gateway mudou em relação à coleta anterior."""

    arp_incomplete: bool = False
    """True se a entrada ARP do gateway está como 'incomplete'."""

    raw_arp_table: str = ""
    """Saída bruta de `arp -a`."""

    error: Optional[str] = None


@dataclass
class PingStats:
    """Estatísticas de ping para um alvo específico."""
    target: str
    """IP ou hostname alvo do ping."""

    packets_sent: int = 0
    packets_received: int = 0
    packet_loss_pct: float = 0.0
    """Percentual de perda de pacotes (0.0–100.0)."""

    latencies_ms: list[float] = field(default_factory=list)
    """Lista de latências individuais em milissegundos."""

    avg_latency_ms: Optional[float] = None
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    """Jitter calculado como desvio padrão das latências."""

    error: Optional[str] = None


@dataclass
class PingResult:
    """Resultado completo da camada de ping (Camada 3)."""
    timestamp: datetime

    gateway: Optional[PingStats]
    """Resultado do ping ao gateway padrão."""

    external_targets: list[PingStats] = field(default_factory=list)
    """Resultados dos pings para alvos externos (1.1.1.1, 8.8.8.8, etc.)."""


@dataclass
class DnsQueryResult:
    """Resultado de uma consulta DNS raw via socket UDP."""
    resolver_ip: str
    """IP do resolver consultado."""

    queried_hostname: str
    """Nome de domínio consultado."""

    resolved_ip: Optional[str]
    """IP resolvido (None em caso de falha)."""

    response_time_ms: Optional[float]
    """Tempo de resposta em milissegundos (None em caso de timeout)."""

    timed_out: bool = False
    error: Optional[str] = None


@dataclass
class DnsResult:
    """Resultado completo das consultas DNS (Camada 4/7)."""
    timestamp: datetime

    queries: list[DnsQueryResult] = field(default_factory=list)
    """Uma consulta por resolver testado."""

    fastest_resolver_ip: Optional[str] = None
    """IP do resolver com menor tempo de resposta."""

    avg_response_ms: Optional[float] = None


@dataclass
class TcpHandshakeResult:
    """Resultado do teste de handshake TCP na porta 443 (Camada 4)."""
    timestamp: datetime

    target_host: str
    target_ip: Optional[str]
    port: int = 443

    handshake_time_ms: Optional[float] = None
    """Tempo do handshake TCP em ms (None em caso de falha)."""

    success: bool = False
    timed_out: bool = False
    error: Optional[str] = None


@dataclass
class SyntheticTestResult:
    """Resultado completo de um ciclo do Módulo 2 (transações sintéticas)."""
    timestamp: datetime

    arp: Optional[ArpResult]
    ping: Optional[PingResult]
    dns: Optional[DnsResult]
    tcp: Optional[TcpHandshakeResult]


# ---------------------------------------------------------------------------
# Módulo 3 — Motor de Decisão
# ---------------------------------------------------------------------------

@dataclass
class CorrelatedEvent:
    """
    Evento do Módulo 1 correlacionado com uma anomalia do Módulo 2.
    Janela de correlação: ±30 segundos.
    """
    event: WifiEvent
    related_metric: str
    """Nome da métrica que apresentou anomalia (ex: 'ping_loss_pct')."""

    time_delta_s: float
    """Diferença em segundos entre o evento e o pico de anomalia."""


@dataclass
class DiagnosticReport:
    """
    Relatório consolidado gerado pelo Módulo 3 para um ciclo de diagnóstico.
    Contém o veredito, nota de saúde e correlações causa-efeito.
    """
    timestamp: datetime
    """Momento de geração do relatório."""

    verdict: VerdictCode
    """Código de veredito hierárquico."""

    verdict_description: str
    """Descrição legível do veredito em PT-BR."""

    health_score: int
    """Nota de saúde de 0 a 100."""

    health_grade: HealthGrade
    """Classificação qualitativa derivada da nota."""

    passive_result: Optional[PassiveCollectionResult]
    """Dados brutos do Módulo 1."""

    synthetic_result: Optional[SyntheticTestResult]
    """Dados brutos do Módulo 2."""

    correlated_events: list[CorrelatedEvent] = field(default_factory=list)
    """Eventos correlacionados com anomalias detectadas."""

    skipped_collections: list[str] = field(default_factory=list)
    """Coletas ignoradas por falta de privilégio ou indisponibilidade."""

    errors: list[str] = field(default_factory=list)
    """Erros não-fatais registrados durante este ciclo."""

    platform: Optional[PlatformInfo] = None
    """Informações da plataforma onde o diagnóstico foi executado."""
