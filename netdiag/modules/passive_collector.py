"""
Módulo 1 — Coleta Passiva.

Responsável por coletar o estado atual da interface Wi-Fi e os logs
de evento do sistema operacional de forma não bloqueante.

Windows:
- Estado da interface: `netsh wlan show interfaces` (sem admin necessário)
- Logs de evento   : `wevtutil qe` no canal WLAN-AutoConfig (requer admin)
  Event IDs: 8001 (conectado), 8002 (falha + Reason Code), 8003 (desconexão),
             10000–10011 (autoconfig)

macOS: assinaturas preservadas, implementação futura.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

from netdiag.models import (
    DisconnectCause,
    DisconnectRecord,
    PassiveCollectionResult,
    Platform,
    PlatformInfo,
    PrivilegeInfo,
    WifiEvent,
    WifiInterfaceState,
)

logger = logging.getLogger("netdiag.modules.passive_collector")

# Namespace XML do Windows Event Log
_WEVT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Mapeamento de Event IDs WLAN para severidade e descrição base
_WLAN_EVENT_MAP: dict[str, tuple[str, str]] = {
    "8001": ("info",    "Interface conectada à rede Wi-Fi com sucesso"),
    "8002": ("error",   "Falha na conexão Wi-Fi (Reason Code 802.11)"),
    "8003": ("warning", "Interface desconectada da rede Wi-Fi"),
    "10000": ("info",   "Serviço WLAN AutoConfig iniciado"),
    "10001": ("info",   "Serviço WLAN AutoConfig parado"),
    "10002": ("warning","Adaptador de rede sem fio habilitado"),
    "10003": ("warning","Adaptador de rede sem fio desabilitado"),
    "10004": ("info",   "Perfil Wi-Fi carregado"),
    "10005": ("warning","Perfil Wi-Fi deletado"),
    "10006": ("warning","Todos os perfis Wi-Fi deletados"),
    "10007": ("info",   "Adaptador Wi-Fi redescoberto"),
    "10008": ("warning","Adaptador Wi-Fi removido"),
    "10009": ("info",   "Varredura de redes iniciada"),
    "10010": ("info",   "Varredura de redes concluída"),
    "10011": ("error",  "Falha na varredura de redes Wi-Fi"),
}

# Reason Codes 802.11 (parcial — os mais frequentes)
_REASON_CODES: dict[str, str] = {
    "0":   "Sucesso",
    "1":   "Motivo não especificado",
    "2":   "Autenticação inválida",
    "3":   "Desautenticação — estação saindo",
    "4":   "Inatividade",
    "6":   "Classe 2 não autenticada",
    "7":   "Classe 3 não associada",
    "8":   "Desassociado — estação saindo",
    "15":  "Falha de handshake 4-way (senha incorreta ou incompatibilidade de segurança)",
    "16":  "Falha no Group Key Handshake",
    "17":  "Incompatibilidade de elemento IE",
    "23":  "IEEE 802.1X falhou",
    "65533": "Rede não visível / SSID não encontrado",
    "65534": "Timeout de operação de rede",
    "65535": "Erro interno do driver",
}

# ---------------------------------------------------------------------------
# Tabela de mapeamento de Reason/ReasonCode para causa de desconexão
# ---------------------------------------------------------------------------

# (substring a buscar no campo Reason/texto — insensitivo a maiúsculas)
# Valor: (DisconnectCause, explicação em PT-BR)
_REASON_TO_CAUSE: list[tuple[str, DisconnectCause, str]] = [
    # --- AP desconectou a máquina ---
    ("peer is leaving", DisconnectCause.AP_KICKED,
     "O ponto de acesso (roteador/AP) enviou um frame de Deautenticação: ele encerrou a conexão ativa. "
     "Causas comuns: reinicialização do AP, mudança de configuração, sobrecarga de clientes ou "
     "firmware bugado no roteador."),
    ("disassociated", DisconnectCause.AP_KICKED,
     "A máquina foi desassociada pelo ponto de acesso. "
     "Pode indicar queda temporária do AP, reinicialização ou expulsão por sobrecarga."),
    ("deauthenticated", DisconnectCause.AP_KICKED,
     "O AP enviou Deautenticação — a máquina foi explicitamente removida da associação. "
     "Verifique se o roteador foi reiniciado ou se há muitos clientes conectados."),
    ("ap is leaving", DisconnectCause.AP_KICKED,
     "O ponto de acesso avisou que está saindo da rede (desligamento/restart planejado do AP)."),
    # --- Inatividade ---
    ("inactivity", DisconnectCause.DEAUTH_INACTIVITY,
     "O AP desconectou a máquina por inatividade (nenhum dado trafegado por tempo prolongado). "
     "Comum em roteadores com power-save agressivo ou configuração de lease timeout curto."),
    # --- Máquina iniciou ---
    ("local", DisconnectCause.USER_INITIATED,
     "A própria máquina (Windows/driver) iniciou a desconexão. "
     "Causas: usuário clicou em Desconectar, troca de perfil de rede, atualização de driver "
     "ou suspensão/hibernação do sistema."),
    ("explicit disconnect", DisconnectCause.USER_INITIATED,
     "Desconexão explícita iniciada pelo sistema operacional ou pelo usuário. "
     "Verifique se houve troca manual de rede ou se um software de VPN/gerenciamento de rede atuou."),
    # --- Falha de autenticação ---
    ("auth", DisconnectCause.AUTH_FAILURE,
     "Falha de autenticação: a senha pode estar incorreta, o certificado expirado ou "
     "o servidor RADIUS inacessível (em redes corporativas WPA2-Enterprise)."),
    ("handshake", DisconnectCause.AUTH_FAILURE,
     "Falha no handshake de segurança (4-way handshake). Causas: senha errada, "
     "descompasso de hora entre cliente e servidor, ou problema de firmware no AP."),
    # --- Roaming ---
    ("roam", DisconnectCause.ROAMING,
     "A máquina realizou roaming: trocou de um ponto de acesso para outro com o mesmo SSID. "
     "Isso é normal em ambientes com múltiplos APs, mas pode causar micro-interrupções."),
    # --- Perda de sinal ---
    ("beacon", DisconnectCause.SIGNAL_LOSS,
     "Perda de beacons do AP: o adaptador parou de receber os sinais de presença do roteador. "
     "Indica sinal fraco, obstáculos físicos ou interferência no canal Wi-Fi."),
    ("signal", DisconnectCause.SIGNAL_LOSS,
     "Perda ou queda de sinal Wi-Fi. O adaptador não conseguiu manter associação com o AP. "
     "Tente aproximar o dispositivo do roteador ou mudar o canal do Wi-Fi."),
    # --- Driver / adaptador ---
    ("driver", DisconnectCause.DRIVER_RESET,
     "O driver do adaptador Wi-Fi foi reiniciado ou travou. "
     "Considere atualizar o driver da placa de rede ou verificar o gerenciador de dispositivos."),
    ("reset", DisconnectCause.DRIVER_RESET,
     "Reset detectado no adaptador Wi-Fi. Pode ser causado por power management agressivo "
     "(Windows desligando o adaptador para economizar energia). Verifique: Gerenciador de Dispositivos "
     "→ Adaptador de rede → Propriedades → Gerenciamento de Energia → desmarque 'Permitir desligar'."),
]


class PassiveCollector:
    """
    Coleta passiva de estado de interface Wi-Fi e logs de evento do SO.

    Detecta automaticamente o SO e delega para a implementação correta.
    Todas as chamadas de subprocess são assíncronas e possuem timeout.
    Falhas parciais são registradas e NÃO interrompem a coleta.
    """

    # Timeout padrão para cada chamada de subprocess (segundos)
    SUBPROCESS_TIMEOUT: int = 15

    def __init__(self, platform: PlatformInfo, privileges: PrivilegeInfo) -> None:
        """
        Inicializa o coletor com informações de plataforma e privilégio.

        Args:
            platform: Plataforma detectada (Windows, macOS).
            privileges: Estado de privilégio do processo.
        """
        self.platform = platform
        self.privileges = privileges

    # -----------------------------------------------------------------------
    # API pública
    # -----------------------------------------------------------------------

    async def collect(self) -> PassiveCollectionResult:
        """
        Executa a coleta passiva completa para o SO atual.

        Returns:
            PassiveCollectionResult com estado da interface e eventos coletados.
        """
        timestamp = datetime.now(tz=timezone.utc)
        errors: list[str] = []

        if self.platform.name == Platform.WINDOWS:
            interface_state, events, events_source, errs = await self._collect_windows()
        elif self.platform.name == Platform.MACOS:
            interface_state, events, events_source, errs = await self._collect_macos()
        else:
            interface_state = None
            events = []
            events_source = "unsupported"
            errs = [f"Plataforma não suportada para coleta passiva: {self.platform.name}"]

        errors.extend(errs)

        # Construir histórico de desconexões a partir dos eventos
        disconnect_history = self._build_disconnect_history(events)

        return PassiveCollectionResult(
            timestamp=timestamp,
            interface_state=interface_state,
            events=events,
            disconnect_history=disconnect_history,
            events_source=events_source,
            errors=errors,
        )

    # -----------------------------------------------------------------------
    # Windows — orquestrador
    # -----------------------------------------------------------------------

    async def _collect_windows(
        self,
    ) -> tuple[Optional[WifiInterfaceState], list[WifiEvent], str, list[str]]:
        """
        Executa a coleta passiva específica para Windows em paralelo.

        Executa netsh e coleta de eventos simultaneamente.

        Returns:
            Tupla (WifiInterfaceState, lista de eventos, fonte dos eventos, lista de erros).
        """
        errors: list[str] = []

        iface_task = asyncio.create_task(
            self._windows_get_interface_state(errors),
            name="windows_netsh",
        )
        events_task = asyncio.create_task(
            self._windows_get_events(errors),
            name="windows_events",
        )

        interface_state, (events, events_source) = await asyncio.gather(iface_task, events_task)
        return interface_state, events, events_source, errors

    # -----------------------------------------------------------------------
    # Windows — Estado da interface (netsh)
    # -----------------------------------------------------------------------

    async def _windows_get_interface_state(
        self, errors: list[str]
    ) -> Optional[WifiInterfaceState]:
        """
        Coleta o estado da interface Wi-Fi via `netsh wlan show interfaces`.

        O parsing extrai: SSID, BSSID, RSSI, canal, banda, autenticação.
        Não requer privilégios elevados.

        Args:
            errors: Lista mutável onde erros não-fatais são acrescentados.

        Returns:
            WifiInterfaceState preenchido, ou None se o comando falhar.
        """
        timestamp = datetime.now(tz=timezone.utc)
        raw = await self._run_subprocess(
            ["netsh", "wlan", "show", "interfaces"],
            errors=errors,
        )

        if raw is None:
            errors.append("netsh wlan show interfaces: falhou ou retornou saída vazia")
            return WifiInterfaceState(
                timestamp=timestamp,
                ssid=None, bssid=None, rssi_dbm=None,
                channel=None, band=None, auth_type=None,
                interface_name=None,
                raw_output="",
                collection_method="netsh",
                error="Comando netsh falhou — sem saída",
            )

        parsed = self._windows_parse_netsh_output(raw)

        # Extrair RSSI: "Sinal" ou "Signal" dependendo do idioma do Windows
        rssi_str = parsed.get("sinal") or parsed.get("signal") or ""
        rssi_dbm: Optional[int] = None
        rssi_match = re.search(r"(-?\d+)\s*dBm", rssi_str, re.IGNORECASE)
        if rssi_match:
            rssi_dbm = int(rssi_match.group(1))
        else:
            # Windows às vezes exibe apenas percentual; converter aproximadamente
            pct_match = re.search(r"(\d+)\s*%", rssi_str)
            if pct_match:
                pct = int(pct_match.group(1))
                # Conversão aproximada: -50 dBm (100%) → -100 dBm (0%)
                rssi_dbm = int(-100 + pct * 0.5)

        # Canal
        channel_str = parsed.get("canal") or parsed.get("channel") or ""
        channel: Optional[int] = None
        ch_match = re.search(r"(\d+)", channel_str)
        if ch_match:
            channel = int(ch_match.group(1))

        # Banda
        radio_type = (
            parsed.get("tipo de rádio") or
            parsed.get("radio type") or
            parsed.get("tipo radio") or ""
        ).lower()

        band: Optional[str] = None
        if "802.11ax" in radio_type or "802.11be" in radio_type:
            # 6 GHz possível em Wi-Fi 6E / 7
            if channel and channel > 200:
                band = "6 GHz"
            elif channel and channel > 14:
                band = "5 GHz"
            else:
                band = "2.4 GHz"
        elif any(x in radio_type for x in ("802.11ac", "802.11n", "802.11a")):
            band = "5 GHz" if (channel and channel > 14) else "2.4 GHz"
        elif any(x in radio_type for x in ("802.11g", "802.11b")):
            band = "2.4 GHz"
        elif channel:
            band = "5 GHz" if channel > 14 else "2.4 GHz"

        return WifiInterfaceState(
            timestamp=timestamp,
            ssid=parsed.get("ssid") or None,
            bssid=parsed.get("bssid") or None,
            rssi_dbm=rssi_dbm,
            channel=channel,
            band=band,
            auth_type=parsed.get("autenticação") or parsed.get("authentication") or None,
            interface_name=parsed.get("nome") or parsed.get("name") or None,
            raw_output=raw,
            collection_method="netsh",
            error=None,
        )

    @staticmethod
    def _windows_parse_netsh_output(raw: str) -> dict[str, str]:
        """
        Faz o parse da saída de texto do `netsh wlan show interfaces`.

        Formato esperado: linhas "  Chave              : Valor"
        Normaliza chaves para minúsculas sem espaços extras para lookup uniforme.

        Args:
            raw: Saída bruta do comando netsh.

        Returns:
            Dicionário {chave_normalizada: valor_bruto}.
        """
        result: dict[str, str] = {}
        for line in raw.splitlines():
            if ":" in line:
                # Divide apenas no primeiro ":"
                key_raw, _, value_raw = line.partition(":")
                key = key_raw.strip().lower()
                value = value_raw.strip()
                if key and value:
                    result[key] = value
        return result

    # -----------------------------------------------------------------------
    # Windows — Logs de evento (wevtutil)
    # -----------------------------------------------------------------------

    async def _windows_get_events(
        self, errors: list[str]
    ) -> tuple[list[WifiEvent], str]:
        """
        Coleta eventos do log WLAN-AutoConfig/Operational.

        Estratégia em cascata (sem bloqueio por nível de admin):
        1. wevtutil qe — tenta sempre; pode funcionar sem admin em sistemas
           com permissão customizada no canal de eventos.
        2. PowerShell Get-WinEvent — fallback se wevtutil falhar com acesso negado.

        Retorna os últimos 200 eventos para cobrir pelo menos 24h de histórico.

        Args:
            errors: Lista mutável onde erros não-fatais são acrescentados.

        Returns:
            Tupla (lista de WifiEvent, fonte utilizada: 'wevtutil'/'powershell'/'sem_acesso').
        """
        # --- Tentativa 1: wevtutil ---
        cmd_wevtutil = [
            "wevtutil", "qe",
            "Microsoft-Windows-WLAN-AutoConfig/Operational",
            "/f:xml",
            "/c:200",
            "/rd:true",  # mais recentes primeiro
        ]
        raw = await self._run_subprocess(cmd_wevtutil, errors=[])

        if raw and raw.strip() and "<Event" in raw:
            logger.info("Eventos WLAN coletados via wevtutil (%d bytes)", len(raw))
            events = self._windows_parse_wevtutil_xml(raw, errors)
            return events, "wevtutil"

        logger.info(
            "wevtutil não retornou eventos — tentando PowerShell Get-WinEvent como fallback"
        )

        # --- Tentativa 2: PowerShell Get-WinEvent ---
        ps_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "try {"
            "  $evts = Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational'"
            "             -MaxEvents 200 -ErrorAction Stop;"
            "  $evts | Where-Object { $_.Id -in @(8001,8002,8003,10000,10001,10002,10003,10008) } |"
            "  ForEach-Object {"
            "    $xml = [xml]$_.ToXml();"
            "    $data = @{};"
            "    $xml.Event.EventData.Data | ForEach-Object { if ($_.Name) { $data[$_.Name]=$_.'#text' } };"
            "    [PSCustomObject]@{"
            "      Id          = $_.Id;"
            "      Time        = $_.TimeCreated.ToUniversalTime().ToString('o');"
            "      Level       = $_.LevelDisplayName;"
            "      Message     = $_.Message;"
            "      Data        = ($data | ConvertTo-Json -Compress)"
            "    }"
            "  } | ConvertTo-Json -Depth 3"
            "} catch { Write-Output '[]' }"
        )
        cmd_ps = [
            "powershell", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", ps_script,
        ]
        ps_raw = await self._run_subprocess(cmd_ps, timeout=20, errors=[])

        if ps_raw and ps_raw.strip() and ps_raw.strip() not in ("", "[]", "null"):
            logger.info("Eventos WLAN coletados via PowerShell Get-WinEvent")
            events = self._windows_parse_powershell_events(ps_raw, errors)
            if events:
                return events, "powershell"

        msg = (
            "Eventos WLAN não acessíveis. "
            "Para habilitar: execute como Administrador ou conceda permissão de leitura "
            "ao canal 'Microsoft-Windows-WLAN-AutoConfig/Operational'."
        )
        logger.warning(msg)
        errors.append(msg)
        return [], "sem_acesso"

    @staticmethod
    def _windows_parse_wevtutil_xml(
        xml_output: str, errors: list[str]
    ) -> list[WifiEvent]:
        """
        Parse do XML do wevtutil e construção de WifiEvent com descrição enriquecida.
        Extrai todos os campos EventData para alimentar _build_disconnect_history.

        Args:
            xml_output: XML bruto retornado pelo wevtutil.
            errors: Lista mutavél de erros (para relatar parse failures).

        Returns:
            Lista de WifiEvent ordenados do mais recente para o mais antigo.
        """
        events: list[WifiEvent] = []
        wrapped = f"<Events>{xml_output}</Events>"

        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError as exc:
            errors.append(f"Falha ao parsear XML do wevtutil: {exc}")
            return []

        ns = _WEVT_NS

        for event_elem in root.findall(f"{{{ns}}}Event"):
            try:
                system_elem = event_elem.find(f"{{{ns}}}System")
                if system_elem is None:
                    continue

                # Event ID
                event_id_elem = system_elem.find(f"{{{ns}}}EventID")
                event_id = (
                    event_id_elem.text.strip()
                    if event_id_elem is not None and event_id_elem.text
                    else "?"
                )

                # Filtrar apenas eventos relevantes
                if event_id not in _WLAN_EVENT_MAP:
                    continue

                # Timestamp
                time_elem = system_elem.find(f"{{{ns}}}TimeCreated")
                timestamp_str = time_elem.get("SystemTime", "") if time_elem is not None else ""
                try:
                    ts = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00").split(".")[0] + "+00:00"
                    )
                except (ValueError, AttributeError):
                    ts = datetime.now(tz=timezone.utc)

                # Dados do EventData — extrair todos os campos como dict
                event_data_elem = event_elem.find(f"{{{ns}}}EventData")
                data_dict: dict[str, str] = {}
                if event_data_elem is not None:
                    for data in event_data_elem.findall(f"{{{ns}}}Data"):
                        name = data.get("Name", "")
                        value = (data.text or "").strip()
                        if name:
                            data_dict[name] = value

                base_desc, severity = _WLAN_EVENT_MAP.get(
                    event_id, (f"Evento WLAN ID {event_id}", "info")
                )
                description = PassiveCollector._enrich_event_description(
                    event_id, base_desc, data_dict
                )

                # Guardar todos os campos no raw_data como JSON para uso posterior
                events.append(WifiEvent(
                    timestamp=ts,
                    event_id=event_id,
                    description=description,
                    raw_data=json.dumps(data_dict, ensure_ascii=False),
                    severity=severity,
                ))

            except Exception as exc:  # noqa: BLE001
                logger.debug("Erro ao parsear evento individual (wevtutil): %s", exc)
                continue

        return events

    @staticmethod
    def _windows_parse_powershell_events(
        ps_output: str, errors: list[str]
    ) -> list[WifiEvent]:
        """
        Parse da saída JSON do Get-WinEvent via PowerShell.

        Cada objeto JSON tem: Id, Time, Level, Message, Data (JSON string).

        Args:
            ps_output: Saída JSON do script PowerShell.
            errors: Lista mutavél de erros.

        Returns:
            Lista de WifiEvent, mais recentes primeiro.
        """
        try:
            raw_list = json.loads(ps_output)
        except json.JSONDecodeError as exc:
            errors.append(f"Falha ao parsear JSON do PowerShell Get-WinEvent: {exc}")
            return []

        # Get-WinEvent com 1 resultado retorna objeto, não lista
        if isinstance(raw_list, dict):
            raw_list = [raw_list]

        if not isinstance(raw_list, list):
            return []

        events: list[WifiEvent] = []
        for item in raw_list:
            try:
                event_id = str(item.get("Id", ""))
                if event_id not in _WLAN_EVENT_MAP:
                    continue

                time_str = item.get("Time", "")
                try:
                    ts = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    ts = datetime.now(tz=timezone.utc)

                # Dados do EventData (JSON dentro do campo Data)
                data_dict: dict[str, str] = {}
                data_raw = item.get("Data", "")
                if data_raw:
                    try:
                        parsed_data = json.loads(data_raw)
                        if isinstance(parsed_data, dict):
                            data_dict = {k: str(v or "") for k, v in parsed_data.items()}
                    except json.JSONDecodeError:
                        pass

                base_desc, severity = _WLAN_EVENT_MAP.get(
                    event_id, (f"Evento WLAN ID {event_id}", "info")
                )
                description = PassiveCollector._enrich_event_description(
                    event_id, base_desc, data_dict
                )

                events.append(WifiEvent(
                    timestamp=ts,
                    event_id=event_id,
                    description=description,
                    raw_data=json.dumps(data_dict, ensure_ascii=False),
                    severity=severity,
                ))

            except Exception as exc:  # noqa: BLE001
                logger.debug("Erro ao parsear evento PowerShell: %s", exc)
                continue

        return events

    @staticmethod
    def _enrich_event_description(
        event_id: str,
        base_desc: str,
        data_dict: dict[str, str],
    ) -> str:
        """
        Enriquece a descrição do evento com campos específicos de cada Event ID.

        8001 — adiciona SSID e BSSID conectado.
        8002 — adiciona SSID e Reason Code traduzido.
        8003 — adiciona SSID, Reason text e IndicaMarcação de quem desconectou.

        Args:
            event_id: ID do evento (string).
            base_desc: Descrição base do evento.
            data_dict: Dicionário de campos EventData.

        Returns:
            Descrição enriquecida em PT-BR.
        """
        ssid = data_dict.get("SSID") or data_dict.get("ProfileName") or ""
        bssid = data_dict.get("BSSID") or data_dict.get("PeerMacAddress") or ""

        if event_id == "8001":
            parts = [base_desc]
            if ssid:
                parts.append(f"SSID: {ssid}")
            if bssid:
                parts.append(f"BSSID: {bssid}")
            return " | ".join(parts)

        if event_id == "8002":
            parts = [base_desc]
            if ssid:
                parts.append(f"SSID: {ssid}")
            # Reason Code
            rc_raw = data_dict.get("ReasonCode") or data_dict.get("FailureReason") or ""
            if rc_raw:
                rc_dec = str(int(rc_raw, 16) if rc_raw.startswith("0x") else rc_raw)
                rc_desc = _REASON_CODES.get(rc_dec, rc_raw)
                parts.append(f"Motivo: {rc_desc}")
            return " | ".join(parts)

        if event_id == "8003":
            parts = [base_desc]
            if ssid:
                parts.append(f"SSID: {ssid}")
            if bssid:
                parts.append(f"BSSID: {bssid}")
            reason_text = (
                data_dict.get("Reason")
                or data_dict.get("DisconnectReason")
                or data_dict.get("ReasonCode")
                or ""
            )
            if reason_text:
                parts.append(f"Razão: {reason_text}")
            return " | ".join(parts)

        return base_desc

    @staticmethod
    def _build_disconnect_history(
        events: list[WifiEvent],
    ) -> list[DisconnectRecord]:
        """
        Analisa a lista de eventos e construói o histórico de desconexões.

        Algoritmo:
        1. Filtrar Event 8003 (desconexões).
        2. Para cada 8003, ler o campo Reason/ReasonCode do raw_data (JSON).
        3. Classificar a causa usando _REASON_TO_CAUSE.
        4. Procurar o Event 8001 seguinte (cronologicamente) para calcular downtime.
        5. Ordenar do mais recente para o mais antigo.

        Args:
            events: Lista de WifiEvent (qualquer ordem).

        Returns:
            Lista de DisconnectRecord, mais recentes primeiro.
        """
        # Ordenar eventos por timestamp (mais antigos primeiro para achar o 8001 seguinte)
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Separar 8001 e 8003
        connects   = [e for e in sorted_events if e.event_id == "8001"]
        disconnects = [e for e in sorted_events if e.event_id == "8003"]

        records: list[DisconnectRecord] = []

        for disc_event in disconnects:
            try:
                # Ler dados do EventData (armazenado como JSON em raw_data)
                data_dict: dict[str, str] = {}
                if disc_event.raw_data:
                    try:
                        parsed = json.loads(disc_event.raw_data)
                        if isinstance(parsed, dict):
                            data_dict = parsed
                    except json.JSONDecodeError:
                        pass

                ssid  = data_dict.get("SSID") or data_dict.get("ProfileName") or None
                bssid = data_dict.get("BSSID") or data_dict.get("PeerMacAddress") or None

                # Texto de razão bruto
                raw_reason = (
                    data_dict.get("Reason")
                    or data_dict.get("DisconnectReason")
                    or data_dict.get("ReasonCode")
                    or ""
                ).strip()

                # Classificar causa
                cause, explanation = PassiveCollector._classify_disconnect_cause(
                    raw_reason, data_dict
                )

                # Procurar reconexão (próximo Event 8001 após esta desconexão)
                reconnected_at: Optional[datetime] = None
                reconnected_ssid: Optional[str] = None
                downtime_s: Optional[float] = None

                for conn_event in connects:
                    if conn_event.timestamp > disc_event.timestamp:
                        reconnected_at = conn_event.timestamp
                        downtime_s = (conn_event.timestamp - disc_event.timestamp).total_seconds()
                        try:
                            c_data = json.loads(conn_event.raw_data) if conn_event.raw_data else {}
                            reconnected_ssid = c_data.get("SSID") or c_data.get("ProfileName")
                        except Exception:  # noqa: BLE001
                            pass
                        break

                records.append(DisconnectRecord(
                    timestamp=disc_event.timestamp,
                    ssid=ssid,
                    bssid=bssid,
                    cause=cause,
                    cause_explanation=explanation,
                    raw_reason=raw_reason or "(não registrado)",
                    reconnected_at=reconnected_at,
                    downtime_seconds=round(downtime_s, 1) if downtime_s is not None else None,
                    reconnected_ssid=reconnected_ssid,
                    event_id="8003",
                    severity="warning",
                ))

            except Exception as exc:  # noqa: BLE001
                logger.debug("Erro ao construir DisconnectRecord: %s", exc)
                continue

        # Ordenar do mais recente para o mais antigo
        records.sort(key=lambda r: r.timestamp, reverse=True)
        return records

    @staticmethod
    def _classify_disconnect_cause(
        raw_reason: str,
        data_dict: dict[str, str],
    ) -> tuple[DisconnectCause, str]:
        """
        Classifica a causa de uma desconexão baseada nos campos do evento.

        Busca correspondência no texto do campo Reason (case-insensitive).
        Se não houver correspondência, verifica o ReasonCode hex.
        Fallback: UNKNOWN.

        Args:
            raw_reason: Texto bruto do campo Reason/DisconnectReason.
            data_dict: Todos os campos EventData do evento.

        Returns:
            Tupla (DisconnectCause, explicação detalhada em PT-BR).
        """
        reason_lower = raw_reason.lower()

        # Verificar na tabela _REASON_TO_CAUSE (ordem importa: mais específico primeiro)
        for keyword, cause, explanation in _REASON_TO_CAUSE:
            if keyword in reason_lower:
                return cause, explanation

        # Verificar ReasonCode hex separadamente
        rc_raw = data_dict.get("ReasonCode", "")
        if rc_raw:
            rc_lower = rc_raw.lower()
            if any(k in rc_lower for k in ("0x40", "0x41", "0x42")):
                return (
                    DisconnectCause.AUTH_FAILURE,
                    "Código de razão indica falha de autenticação. "
                    "Verifique a senha e as configurações de segurança do AP.",
                )

        # Sem reason registrado — perda abrupta de sinal
        if not raw_reason or raw_reason == "(não registrado)":
            return (
                DisconnectCause.SIGNAL_LOSS,
                "Desconexão sem razão registrada: provavelmente perda abrupta de sinal "
                "ou desligamento inesperado do adaptador Wi-Fi. "
                "Verifique a força do sinal e a estabilidade do driver.",
            )

        return (
            DisconnectCause.UNKNOWN,
            f"Causa não identificada automaticamente. Razão bruta: '{raw_reason}'. "
            "Consulte o Visualizador de Eventos do Windows para mais detalhes.",
        )

    # -----------------------------------------------------------------------
    # macOS — implementação completa
    # -----------------------------------------------------------------------

    async def _collect_macos(
        self,
    ) -> tuple[Optional[WifiInterfaceState], list[WifiEvent], str, list[str]]:
        """
        Executa a coleta passiva específica para macOS em paralelo.

        Fontes:
        - Estado da interface: `wdutil info` (requer sudo) ou system_profiler (fallback).
        - Logs de evento: `log show --predicate 'subsystem == "com.apple.wifi"' --last 30m`.

        Returns:
            Tupla (WifiInterfaceState, lista de eventos, fonte dos eventos, lista de erros).
        """
        errors: list[str] = []

        iface_task = asyncio.create_task(
            self._macos_get_interface_state(errors),
            name="macos_interface",
        )
        events_task = asyncio.create_task(
            self._macos_get_events(errors),
            name="macos_events",
        )

        interface_state, events_tuple = await asyncio.gather(iface_task, events_task)
        events, events_source = events_tuple
        return interface_state, events, events_source, errors

    async def _macos_get_interface_state(
        self, errors: list[str]
    ) -> Optional[WifiInterfaceState]:
        """
        Coleta o estado da interface Wi-Fi no macOS.

        Estratégia em cascata:
        1. `wdutil info` (requer sudo, macOS 12+) — mais detalhado.
        2. `system_profiler SPAirPortDataType -json` — sem sudo, macOS 12+.
        3. `system_profiler SPAirPortDataType` (texto) — fallback para macOS antigos.

        IMPORTANTE: NÃO usa `airport -I` (removido/quebrado a partir do macOS 14.4).

        Args:
            errors: Lista mutável onde erros não-fatais são acrescentados.

        Returns:
            WifiInterfaceState preenchido, ou stub de erro se tudo falhar.
        """
        timestamp = datetime.now(tz=timezone.utc)

        # --- Estratégia 1: wdutil info (requer sudo) ---
        if self.privileges.is_elevated:
            raw_wdutil = await self._run_subprocess(["wdutil", "info"], errors=[])
            if raw_wdutil:
                parsed = self._macos_parse_wdutil_output(raw_wdutil)
                if parsed.get("ssid"):
                    logger.info("Estado Wi-Fi coletado via wdutil info")
                    return self._macos_build_interface_state(
                        parsed, raw_wdutil, "wdutil", timestamp
                    )

        # --- Estratégia 2: system_profiler -json (macOS 12+, sem sudo) ---
        raw_json = await self._run_subprocess(
            ["system_profiler", "SPAirPortDataType", "-json"],
            timeout=20,
            errors=[],
        )
        if raw_json:
            state = self._macos_parse_system_profiler_json(raw_json, timestamp)
            if state:
                logger.info("Estado Wi-Fi coletado via system_profiler -json")
                return state

        # --- Estratégia 3: system_profiler texto (fallback macOS antigos) ---
        raw_text = await self._run_subprocess(
            ["system_profiler", "SPAirPortDataType"],
            timeout=20,
            errors=errors,
        )
        if raw_text:
            parsed = self._macos_parse_system_profiler_text(raw_text)
            if parsed.get("ssid") or parsed.get("interface_name"):
                logger.info("Estado Wi-Fi coletado via system_profiler (texto)")
                return self._macos_build_interface_state(
                    parsed, raw_text, "system_profiler", timestamp
                )

        msg = "Não foi possível coletar estado da interface Wi-Fi no macOS."
        errors.append(msg)
        return WifiInterfaceState(
            timestamp=timestamp,
            ssid=None, bssid=None, rssi_dbm=None,
            channel=None, band=None, auth_type=None,
            interface_name=None,
            raw_output="",
            collection_method="system_profiler",
            error=msg,
        )

    @staticmethod
    def _macos_parse_system_profiler_json(
        raw_json: str,
        timestamp: datetime,
    ) -> Optional[WifiInterfaceState]:
        """
        Parseia a saída JSON de `system_profiler SPAirPortDataType -json`.

        Args:
            raw_json: JSON bruto do system_profiler.
            timestamp: Timestamp da coleta.

        Returns:
            WifiInterfaceState preenchido, ou None se não houver rede ativa.
        """
        try:
            data = json.loads(raw_json)
            items = data.get("SPAirPortDataType", [])
            if not items:
                return None

            item = items[0]
            ifaces = item.get("spairport_wireless_interfaces", [])
            interface_name: Optional[str] = ifaces[0].get("_name") if ifaces else None

            net_info = item.get("spairport_current_network_information")
            if not net_info:
                return None

            ssid = net_info.get("_name")
            bssid = net_info.get("spairport_network_bssid")

            # RSSI: "spairport_network_signal_noise" ex: "-65 dBm / -90 dBm"
            rssi_dbm: Optional[int] = None
            rssi_match = re.search(
                r"(-?\d+)\s*dBm",
                net_info.get("spairport_network_signal_noise", ""),
            )
            if rssi_match:
                rssi_dbm = int(rssi_match.group(1))

            # Canal e banda: ex "Channel 6 (2.4 GHz, 20 MHz)"
            channel: Optional[int] = None
            band: Optional[str] = None
            channel_str = net_info.get("spairport_network_channel", "")
            ch_match = re.search(r"Channel\s+(\d+)", channel_str, re.IGNORECASE)
            if ch_match:
                channel = int(ch_match.group(1))
            if "6 GHz" in channel_str:
                band = "6 GHz"
            elif "5" in channel_str or (channel and channel > 14):
                band = "5 GHz"
            elif "2.4" in channel_str or (channel and channel <= 14):
                band = "2.4 GHz"

            auth_type = net_info.get("spairport_network_security_mode")

            return WifiInterfaceState(
                timestamp=timestamp,
                ssid=ssid,
                bssid=bssid,
                rssi_dbm=rssi_dbm,
                channel=channel,
                band=band,
                auth_type=auth_type,
                interface_name=interface_name,
                raw_output=raw_json[:2000],
                collection_method="system_profiler_json",
                error=None,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Falha ao parsear system_profiler JSON: %s", exc)
            return None

    @staticmethod
    def _macos_parse_system_profiler_text(raw: str) -> dict[str, str]:
        """
        Parseia a saída texto de `system_profiler SPAirPortDataType`.

        Args:
            raw: Saída bruta do comando.

        Returns:
            Dicionário {campo_normalizado: valor}.
        """
        result: dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if ":" in line:
                key_raw, _, value_raw = line.partition(":")
                key = key_raw.strip().lower().replace(" ", "_")
                value = value_raw.strip()
                if key and value:
                    result[key] = value
        return result

    @staticmethod
    def _macos_build_interface_state(
        parsed: dict[str, str],
        raw_output: str,
        method: str,
        timestamp: datetime,
    ) -> WifiInterfaceState:
        """
        Constrói WifiInterfaceState a partir de um dict de campos macOS.

        Suporta campos de wdutil e de system_profiler (texto).

        Args:
            parsed: Dicionário de campos normalizados.
            raw_output: Saída bruta para debug.
            method: Método de coleta utilizado ('wdutil', 'system_profiler').
            timestamp: Timestamp da coleta.

        Returns:
            WifiInterfaceState preenchido.
        """
        ssid = (
            parsed.get("ssid")
            or parsed.get("current_network")
            or parsed.get("network_name")
            or None
        )
        bssid = parsed.get("bssid") or parsed.get("ap_mac_address") or None

        rssi_dbm: Optional[int] = None
        for key in ("rssi", "rssi_(dbm)", "rssi_dbm", "signal_/_noise", "signal"):
            rssi_str = parsed.get(key, "")
            if rssi_str:
                m = re.search(r"(-?\d+)", rssi_str)
                if m:
                    rssi_dbm = int(m.group(1))
                    break

        channel: Optional[int] = None
        ch_str = parsed.get("channel") or parsed.get("network_channel") or ""
        ch_match = re.search(r"(\d+)", ch_str)
        if ch_match:
            channel = int(ch_match.group(1))

        band: Optional[str] = None
        band_str = (
            parsed.get("band") or parsed.get("network_band") or ch_str or ""
        ).lower()
        if "6" in band_str and "ghz" in band_str:
            band = "6 GHz"
        elif "5" in band_str or (channel and channel > 14):
            band = "5 GHz"
        elif "2.4" in band_str or (channel and channel <= 14):
            band = "2.4 GHz"

        interface_name = (
            parsed.get("interface_name")
            or parsed.get("bsd_device_name")
            or None
        )
        auth_type = parsed.get("security") or parsed.get("security_type") or None

        return WifiInterfaceState(
            timestamp=timestamp,
            ssid=ssid,
            bssid=bssid,
            rssi_dbm=rssi_dbm,
            channel=channel,
            band=band,
            auth_type=auth_type,
            interface_name=interface_name,
            raw_output=raw_output[:2000],
            collection_method=method,
            error=None,
        )

    async def _macos_get_events(
        self, errors: list[str]
    ) -> tuple[list[WifiEvent], str]:
        """
        Coleta logs de rede no macOS via `log show`.

        Predicado primário : subsystem == "com.apple.wifi" --info
        Fallback           : subsystem wifi OR process airportd, sem --info.

        Args:
            errors: Lista mutável onde erros não-fatais são acrescentados.

        Returns:
            Tupla (lista de WifiEvent, fonte utilizada).
        """
        # --- Tentativa 1: log show com --info ---
        cmd = [
            "log", "show",
            "--predicate", 'subsystem == "com.apple.wifi"',
            "--last", "30m",
            "--style", "syslog",
            "--info",
        ]
        raw = await self._run_subprocess(cmd, timeout=20, errors=[])
        if raw and len(raw.strip()) > 50:
            events = self._macos_parse_log_output(raw)
            if events:
                logger.info("Eventos Wi-Fi coletados via log show (%d eventos)", len(events))
                return events, "log_show"

        # --- Tentativa 2: fallback airportd, sem --info ---
        cmd2 = [
            "log", "show",
            "--predicate",
            'subsystem == "com.apple.wifi" OR process == "airportd"',
            "--last", "30m",
            "--style", "syslog",
        ]
        raw2 = await self._run_subprocess(cmd2, timeout=20, errors=[])
        if raw2 and len(raw2.strip()) > 50:
            events = self._macos_parse_log_output(raw2)
            if events:
                logger.info(
                    "Eventos Wi-Fi coletados via log show (fallback, %d eventos)",
                    len(events),
                )
                return events, "log_show_airportd"

        msg = (
            "Logs Wi-Fi macOS não disponíveis neste ciclo. "
            "Para habilitar, execute: "
            "sudo log show --predicate 'subsystem == \"com.apple.wifi\"' --last 30m"
        )
        logger.warning(msg)
        errors.append(msg)
        return [], "sem_acesso"

    @staticmethod
    def _macos_parse_wdutil_output(raw: str) -> dict[str, str]:
        """
        Faz o parse da saída do `wdutil info`.

        Formato esperado (macOS 12+)::

            WIFI:
              SSID          : MyNetwork
              BSSID         : aa:bb:cc:dd:ee:ff
              RSSI (dBm)    : -65
              Channel       : 6
              Security      : WPA2 Personal

        Args:
            raw: Saída bruta do comando wdutil.

        Returns:
            Dicionário {campo_normalizado: valor_bruto}.
        """
        result: dict[str, str] = {}
        in_wifi = False
        _OTHER = {"BT", "AWDL", "LLW", "NAN", "GENERAL", "BONJOUR", "P2P", "SYSTEM"}

        for line in raw.splitlines():
            stripped = line.strip()

            if stripped.upper().startswith("WIFI:"):
                in_wifi = True
                continue

            # Detectar outra seção de topo (sem indentação)
            if in_wifi and stripped and not line[0].isspace():
                section = stripped.split(":")[0].strip().upper()
                if section in _OTHER:
                    in_wifi = False
                    continue

            if in_wifi and ":" in stripped:
                key_raw, _, value_raw = stripped.partition(":")
                key = (
                    key_raw.strip()
                    .lower()
                    .replace(" ", "_")
                    .replace("(", "")
                    .replace(")", "")
                )
                value = value_raw.strip()
                if key and value:
                    result[key] = value

        return result

    @staticmethod
    def _macos_parse_log_output(raw: str) -> list[WifiEvent]:
        """
        Faz o parse das linhas de log retornadas pelo `log show --style syslog`.

        Formatos suportados:
        - ISO  : ``2024-01-15 10:30:00.123456+0000  localhost airportd[123]: ...``
        - Syslog: ``Jan 15 10:30:00.123 kernel[0]: ...``

        Args:
            raw: Saída bruta do comando log show.

        Returns:
            Lista de WifiEvent parseados (máx. 200, apenas eventos relevantes).
        """
        _KEYWORDS: list[tuple[str, str, str]] = [
            ("joined",          "info",    "Interface conectada à rede Wi-Fi"),
            ("associated",      "info",    "Interface associada ao ponto de acesso"),
            ("connected",       "info",    "Conexão Wi-Fi estabelecida"),
            ("disassociated",   "warning", "Interface desassociada do AP"),
            ("disconnected",    "warning", "Interface desconectada da rede Wi-Fi"),
            ("deauthenticated", "warning", "Interface desautenticada pelo AP"),
            ("roam",            "info",    "Roaming: troca de ponto de acesso"),
            ("scan complete",   "info",    "Varredura de redes concluída"),
            ("scan",            "info",    "Varredura de redes Wi-Fi"),
            ("failed",          "error",   "Falha em operação Wi-Fi"),
            ("timeout",         "warning", "Timeout em operação Wi-Fi"),
            ("handshake",       "warning", "Handshake de segurança Wi-Fi"),
            ("auth",            "info",    "Autenticação Wi-Fi"),
        ]
        _WIFI_TERMS = frozenset((
            "wifi", "wlan", "airport", "bssid", "ssid", "80211",
            "disassociat", "associat", "roam", "connect", "disconnect",
            "handshake", "auth", "beacon", "scan", "channel", "airportd",
        ))
        _MONTH_MAP = {
            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
        }

        ts_iso_re = re.compile(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[\+\-]\d{4}|Z)?\s+"
        )
        ts_syslog_re = re.compile(
            r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
        )

        events: list[WifiEvent] = []
        count = 0

        for line in raw.splitlines():
            if count >= 200:
                break
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Timestamp"):
                continue

            line_lower = line.lower()
            if not any(t in line_lower for t in _WIFI_TERMS):
                continue

            ts: Optional[datetime] = None
            msg_part = line

            m_iso = ts_iso_re.match(line)
            if m_iso:
                try:
                    ts = datetime.fromisoformat(
                        m_iso.group(1).replace(" ", "T") + "+00:00"
                    )
                    msg_part = line[m_iso.end():]
                except ValueError:
                    pass

            if ts is None:
                m_syslog = ts_syslog_re.match(line)
                if m_syslog:
                    try:
                        month = _MONTH_MAP.get(m_syslog.group(1), 1)
                        day = int(m_syslog.group(2))
                        t_parts = m_syslog.group(3).split(":")
                        now = datetime.now(tz=timezone.utc)
                        ts = datetime(
                            now.year, month, day,
                            int(t_parts[0]), int(t_parts[1]), int(t_parts[2]),
                            tzinfo=timezone.utc,
                        )
                        msg_part = line[m_syslog.end():]
                    except (ValueError, IndexError):
                        pass

            if ts is None:
                ts = datetime.now(tz=timezone.utc)

            msg_lower2 = msg_part.lower()
            severity = "info"
            description = msg_part[:200]

            for keyword, sev, base_desc in _KEYWORDS:
                if keyword in msg_lower2:
                    severity = sev
                    ssid_match = re.search(r'"([^"]{1,64})"', msg_part)
                    description = (
                        f"{base_desc} — SSID: {ssid_match.group(1)}"
                        if ssid_match
                        else f"{base_desc}: {msg_part[:120]}"
                    )
                    break

            events.append(WifiEvent(
                timestamp=ts,
                event_id=None,
                description=description,
                raw_data=msg_part[:500],
                severity=severity,
            ))
            count += 1

        return events

    # -----------------------------------------------------------------------
    # Utilitário assíncrono de subprocess
    # -----------------------------------------------------------------------

    async def _run_subprocess(
        self,
        cmd: list[str],
        timeout: int = SUBPROCESS_TIMEOUT,
        errors: Optional[list[str]] = None,
    ) -> Optional[str]:
        """
        Executa um subprocesso de forma assíncrona com timeout e captura de erros.

        Usa `asyncio.create_subprocess_exec` — NUNCA subprocess.run bloqueante.
        Em caso de timeout, o processo é terminado e a falha é registrada.

        Args:
            cmd: Lista de strings representando o comando e seus argumentos.
            timeout: Timeout em segundos (padrão: SUBPROCESS_TIMEOUT).
            errors: Lista mutável onde mensagens de erro são acrescentadas.

        Returns:
            stdout do processo como string, ou None em caso de falha.
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
            stderr_text = stderr_b.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0:
                msg = f"Comando '{cmd_str}' retornou código {proc.returncode}"
                if stderr_text:
                    msg += f": {stderr_text[:200]}"
                logger.warning(msg)
                if errors is not None:
                    errors.append(msg)
                # Retornar stdout mesmo em caso de código não-zero (netsh faz isso)
                return stdout if stdout else None

            return stdout

        except asyncio.TimeoutError:
            msg = f"Timeout ({timeout}s) ao executar '{cmd_str}'"
            logger.warning(msg)
            if errors is not None:
                errors.append(msg)
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
            return None

        except FileNotFoundError:
            msg = f"Comando não encontrado: '{cmd[0]}'"
            logger.warning(msg)
            if errors is not None:
                errors.append(msg)
            return None

        except Exception as exc:  # noqa: BLE001
            msg = f"Erro inesperado ao executar '{cmd_str}': {exc}"
            logger.error(msg, exc_info=True)
            if errors is not None:
                errors.append(msg)
            return None
