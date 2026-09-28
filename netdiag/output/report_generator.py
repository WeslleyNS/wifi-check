"""
Gerador de relatórios HTML, TXT e ZIP para o modo 'doctor'.

Produz:
1. HTML autocontido (CSS inline, sem CDN) com nota de saúde, seções
   colapsáveis, tabelas de métricas e logs brutos destacados.
2. TXT resumo executivo (5-10 linhas, para uso em chamados de suporte).
3. ZIP com todos os artefatos brutos em JSON por módulo.
"""

from __future__ import annotations

import html
import json
import logging
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def _esc(val: Any) -> str:
    """Escapa dados dinâmicos para prevenir vulnerabilidades XSS no relatório HTML."""
    if val is None:
        return "—"
    return html.escape(str(val))

from netdiag.models import (
    DiagnosticReport,
    HealthGrade,
    Platform,
    PlatformInfo,
    VerdictCode,
)
from netdiag.utils.platform import get_netdiag_logs_dir

logger = logging.getLogger("netdiag.output.report_generator")

# Mapeamento de cor por nota de saúde
_GRADE_COLOR: dict[HealthGrade, str] = {
    HealthGrade.OPTIMAL:  "#22c55e",   # verde
    HealthGrade.STABLE:   "#3b82f6",   # azul
    HealthGrade.DEGRADED: "#f59e0b",   # âmbar
    HealthGrade.CRITICAL: "#ef4444",   # vermelho
}

_VERDICT_COLOR: dict[VerdictCode, str] = {
    VerdictCode.OK:                   "#22c55e",
    VerdictCode.NETWORK_INSTABILITY:  "#f59e0b",
    VerdictCode.FIREWALL_BLOCK:       "#f97316",
    VerdictCode.DNS_FAILURE:          "#f97316",
    VerdictCode.NO_WAN:               "#ef4444",
    VerdictCode.L2_ISOLATION:         "#dc2626",
    VerdictCode.UNKNOWN:              "#6b7280",
}

_SEVERITY_COLOR = {
    "info":    "#3b82f6",
    "warning": "#f59e0b",
    "error":   "#ef4444",
}


class ReportGenerator:
    """
    Gerador de relatórios de diagnóstico nos formatos HTML, TXT e ZIP.
    """

    def __init__(self, platform: PlatformInfo) -> None:
        """
        Inicializa o gerador com informações da plataforma.

        Args:
            platform: Plataforma detectada para adaptar caminhos de saída.
        """
        self.platform = platform

    # -----------------------------------------------------------------------
    # API pública
    # -----------------------------------------------------------------------

    async def generate_doctor_output(
        self,
        report: DiagnosticReport,
        output_dir: Optional[str] = None,
    ) -> Path:
        """
        Gera todos os artefatos de saída do modo doctor.

        Arquivos gerados (com timestamp YYYYMMDD-HHMMSS):
        - netdiag-report-<ts>.html
        - netdiag-report-<ts>.txt
        - netdiag-report-<ts>.zip

        Args:
            report: DiagnosticReport consolidado pelo Módulo 3.
            output_dir: Diretório de saída. Se None, usa o Desktop com fallback.

        Returns:
            Path do diretório onde os arquivos foram salvos.
        """
        out_dir = self._resolve_output_dir(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        ts_str = report.timestamp.strftime("%Y%m%d-%H%M%S")
        base_name = f"netdiag-report-{ts_str}"

        # HTML
        html_content = self._generate_html(report)
        html_path = out_dir / f"{base_name}.html"
        html_path.write_text(html_content, encoding="utf-8")
        logger.info("Relatório HTML salvo em: %s", html_path)

        # TXT
        txt_content = self._generate_txt_summary(report)
        txt_path = out_dir / f"{base_name}.txt"
        txt_path.write_text(txt_content, encoding="utf-8")
        logger.info("Resumo TXT salvo em: %s", txt_path)

        # ZIP com JSONs brutos
        zip_path = self._generate_zip(report, out_dir, ts_str)
        logger.info("Artefatos ZIP salvos em: %s", zip_path)

        print(f"\n  [HTML] Relatorio HTML : {html_path}")
        print(f"  [TXT]  Resumo TXT    : {txt_path}")
        print(f"  [ZIP]  Artefatos ZIP : {zip_path}")

        return out_dir

    # -----------------------------------------------------------------------
    # Resolução do diretório de saída
    # -----------------------------------------------------------------------

    def _resolve_output_dir(self, output_dir: Optional[str]) -> Path:
        """
        Resolve o diretório de saída dos relatórios.

        Se ``output_dir`` for fornecido, usa esse caminho.
        Caso contrário, usa ``Desktop/NetDiag-Logs/`` (criado automaticamente),
        que é a pasta central para todos os arquivos gerados pelo NetDiag.

        Args:
            output_dir: Caminho fornecido pelo usuário (ou None para padrão).

        Returns:
            Path do diretório de saída (já criado no disco).
        """
        if output_dir:
            p = Path(output_dir)
            p.mkdir(parents=True, exist_ok=True)
            return p

        return get_netdiag_logs_dir()

    # -----------------------------------------------------------------------
    # HTML autocontido
    # -----------------------------------------------------------------------

    def _generate_html(self, report: DiagnosticReport) -> str:
        """
        Gera o relatório HTML autocontido com CSS inline, sem CDN.

        Inclui: medidor de nota, seções colapsáveis (<details>/<summary>),
        tabelas de latência/jitter, logs brutos em <pre>, destaques visuais.

        Args:
            report: DiagnosticReport com todos os dados.

        Returns:
            String HTML completa e autocontida.
        """
        grade_color = _GRADE_COLOR.get(report.health_grade, "#6b7280")
        verdict_color = _VERDICT_COLOR.get(report.verdict, "#6b7280")
        ts_local = report.timestamp.strftime("%d/%m/%Y %H:%M:%S UTC")
        platform_str = (
            f"{report.platform.os_version} ({report.platform.architecture})"
            if report.platform else "Desconhecido"
        )

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetDiag Agent — Relatório de Diagnóstico</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #263347;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
    --green: #22c55e; --blue: #3b82f6; --amber: #f59e0b;
    --red: #ef4444; --orange: #f97316;
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Code', 'Consolas', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: var(--font); font-size: 14px; line-height: 1.6;
    padding: 24px;
  }}
  .header {{
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid var(--border); border-radius: 12px;
    padding: 32px; margin-bottom: 24px;
    display: grid; grid-template-columns: 1fr auto; gap: 24px;
    align-items: center;
  }}
  .header h1 {{ font-size: 22px; font-weight: 700; color: #f1f5f9; }}
  .header .meta {{ color: var(--muted); font-size: 12px; margin-top: 6px; }}
  .meter-wrap {{ text-align: center; }}
  .meter-circle {{
    width: 110px; height: 110px; border-radius: 50%;
    background: conic-gradient({grade_color} {report.health_score * 3.6}deg, #334155 0deg);
    display: flex; align-items: center; justify-content: center;
    position: relative;
  }}
  .meter-inner {{
    width: 80px; height: 80px; border-radius: 50%;
    background: #1e293b;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }}
  .meter-score {{ font-size: 24px; font-weight: 800; color: {grade_color}; line-height: 1; }}
  .meter-label {{ font-size: 10px; color: var(--muted); margin-top: 2px; }}
  .meter-grade {{ font-size: 12px; color: {grade_color}; margin-top: 6px; font-weight: 600; }}
  .verdict-banner {{
    background: {verdict_color}18;
    border: 1px solid {verdict_color}44;
    border-left: 4px solid {verdict_color};
    border-radius: 8px; padding: 16px 20px; margin-bottom: 24px;
  }}
  .verdict-banner .code {{
    font-size: 11px; font-family: var(--mono); color: {verdict_color};
    font-weight: 700; letter-spacing: 0.05em; margin-bottom: 4px;
  }}
  .verdict-banner .desc {{ color: var(--text); font-size: 14px; }}
  details {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; margin-bottom: 16px; overflow: hidden;
  }}
  summary {{
    padding: 14px 20px; font-weight: 600; cursor: pointer;
    display: flex; align-items: center; gap: 10px;
    user-select: none; list-style: none;
    border-bottom: 1px solid transparent; transition: background 0.15s;
  }}
  summary:hover {{ background: var(--surface2); }}
  details[open] summary {{ border-bottom-color: var(--border); }}
  summary::before {{ content: "▶"; font-size: 10px; color: var(--muted); transition: transform 0.2s; }}
  details[open] summary::before {{ transform: rotate(90deg); }}
  .section-body {{ padding: 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{
    background: var(--surface2); color: var(--muted);
    text-align: left; padding: 8px 12px; font-weight: 600;
    font-size: 11px; letter-spacing: 0.04em; text-transform: uppercase;
    border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #1e293b; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--surface2); }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 9999px;
    font-size: 11px; font-weight: 600;
  }}
  .badge-ok    {{ background: #22c55e22; color: #22c55e; }}
  .badge-warn  {{ background: #f59e0b22; color: #f59e0b; }}
  .badge-error {{ background: #ef444422; color: #ef4444; }}
  .badge-info  {{ background: #3b82f622; color: #3b82f6; }}
  pre {{
    background: #0a0f1a; border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; overflow-x: auto; font-family: var(--mono);
    font-size: 12px; line-height: 1.5; color: #94a3b8; white-space: pre-wrap;
    word-break: break-all; max-height: 400px; overflow-y: auto;
  }}
  .kv-grid {{ display: grid; grid-template-columns: 180px 1fr; gap: 4px 12px; }}
  .kv-key {{ color: var(--muted); font-size: 12px; }}
  .kv-val {{ font-weight: 500; font-size: 13px; }}
  .tag-list {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .tag {{
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 6px; padding: 3px 10px; font-size: 12px; color: var(--muted);
  }}
  .warn-box {{
    background: #f59e0b11; border: 1px solid #f59e0b44;
    border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;
    color: #fbbf24; font-size: 13px;
  }}
  .err-box {{
    background: #ef444411; border: 1px solid #ef444444;
    border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;
    color: #fca5a5; font-size: 13px;
  }}
  footer {{
    margin-top: 32px; text-align: center;
    color: var(--muted); font-size: 11px;
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>🔍 NetDiag Agent — Relatório de Diagnóstico</h1>
    <div class="meta">
      🕐 {ts_local} &nbsp;|&nbsp;
      💻 {platform_str}
    </div>
  </div>
  <div class="meter-wrap">
    <div class="meter-circle">
      <div class="meter-inner">
        <span class="meter-score">{report.health_score}</span>
        <span class="meter-label">/ 100</span>
      </div>
    </div>
    <div class="meter-grade">{report.health_grade.value.upper()}</div>
  </div>
</div>

<div class="verdict-banner">
  <div class="code">⚡ VEREDITO: {report.verdict.value}</div>
  <div class="desc">{report.verdict_description}</div>
</div>

{self._html_skipped_section(report)}
{self._html_errors_section(report)}

<!-- Resumo Executivo -->
<details open>
  <summary>📊 Resumo de Conectividade</summary>
  <div class="section-body">
    {self._html_connectivity_summary(report)}
  </div>
</details>

<!-- Tabela de Ping -->
<details open>
  <summary>📡 Latência e Jitter (Ping)</summary>
  <div class="section-body">
    {self._html_ping_table(report)}
  </div>
</details>

<!-- Tabela DNS -->
<details open>
  <summary>🌐 Resolução DNS</summary>
  <div class="section-body">
    {self._html_dns_table(report)}
  </div>
</details>

<!-- TCP Handshake -->
<details>
  <summary>🔒 TCP Handshake (porta 443)</summary>
  <div class="section-body">
    {self._html_tcp_section(report)}
  </div>
</details>

<!-- ARP / Gateway -->
<details>
  <summary>🔗 Gateway e ARP (Camada 2)</summary>
  <div class="section-body">
    {self._html_arp_section(report)}
  </div>
</details>

<!-- Interface Wi-Fi -->
<details>
  <summary>📶 Estado da Interface Wi-Fi</summary>
  <div class="section-body">
    {self._html_interface_section(report)}
  </div>
</details>

<!-- Driver Wi-Fi -->
<details open>
  <summary>💻 Driver Wi-Fi</summary>
  <div class="section-body">
    {self._html_driver_section(report)}
  </div>
</details>

<!-- Histórico de Desconexões -->
<details open>
  <summary>📡 Histórico de Desconexões (Módulo 1)</summary>
  <div class="section-body">
    {self._html_disconnect_history(report)}
  </div>
</details>

<!-- Eventos Correlacionados -->
{self._html_correlated_events_section(report)}

<!-- Eventos Brutos -->
<details>
  <summary>📋 Log de Eventos de Rede (brutos)</summary>
  <div class="section-body">
    {self._html_raw_events(report)}
  </div>
</details>

<footer>
  Gerado por NetDiag Agent v0.1.0-alpha &nbsp;|&nbsp;
  {ts_local}
</footer>

</body>
</html>"""

    def _html_skipped_section(self, report: DiagnosticReport) -> str:
        if not report.skipped_collections:
            return ""
        items = "".join(f"<li>{e}</li>" for e in report.skipped_collections)
        return f"""<div class="warn-box">
  ⚠️ <strong>Coletas ignoradas por falta de privilégio:</strong>
  <ul style="margin-top:6px;padding-left:18px">{items}</ul>
</div>"""

    def _html_errors_section(self, report: DiagnosticReport) -> str:
        if not report.errors:
            return ""
        items = "".join(f"<li>{e}</li>" for e in report.errors)
        return f"""<div class="err-box">
  ❌ <strong>Erros não-fatais registrados:</strong>
  <ul style="margin-top:6px;padding-left:18px">{items}</ul>
</div>"""

    def _html_connectivity_summary(self, report: DiagnosticReport) -> str:
        rows = []

        def _row(label: str, value: str, badge_class: str = "") -> str:
            badge = f'<span class="badge {badge_class}">{value}</span>' if badge_class else value
            return f"<tr><td style='color:#94a3b8;width:200px'>{label}</td><td>{badge}</td></tr>"

        if report.synthetic_result:
            s = report.synthetic_result
            # Gateway
            if s.ping and s.ping.gateway:
                gw = s.ping.gateway
                if gw.packets_received > 0:
                    rows.append(_row("Gateway (ping)", f"OK — {gw.avg_latency_ms}ms", "badge-ok"))
                else:
                    rows.append(_row("Gateway (ping)", "SEM RESPOSTA", "badge-error"))

            # Externo
            if s.ping and s.ping.external_targets:
                ok_ext = [t for t in s.ping.external_targets if t.packets_received > 0]
                if ok_ext:
                    best = min(ok_ext, key=lambda t: t.avg_latency_ms or 9999)
                    rows.append(_row("Internet (ping)", f"OK — {best.avg_latency_ms}ms via {best.target}", "badge-ok"))
                else:
                    rows.append(_row("Internet (ping)", "SEM RESPOSTA", "badge-error"))

            # DNS
            if s.dns and s.dns.queries:
                ok_dns = [q for q in s.dns.queries if q.resolved_ip]
                if ok_dns:
                    best_dns = min(ok_dns, key=lambda q: q.response_time_ms or 9999)
                    color = "badge-warn" if (best_dns.response_time_ms or 0) > 200 else "badge-ok"
                    rows.append(_row("DNS", f"OK — {best_dns.response_time_ms}ms ({best_dns.resolver_ip})", color))
                else:
                    rows.append(_row("DNS", "FALHA", "badge-error"))

            # TCP
            if s.tcp:
                if s.tcp.success:
                    color = "badge-warn" if (s.tcp.handshake_time_ms or 0) > 300 else "badge-ok"
                    rows.append(_row("TCP 443", f"OK — {s.tcp.handshake_time_ms}ms", color))
                else:
                    rows.append(_row("TCP 443", "FALHA", "badge-error"))

            # ARP
            if s.arp:
                if s.arp.mac_changed:
                    rows.append(_row("ARP Gateway", "MAC ALTERADO ⚠️", "badge-warn"))
                elif s.arp.arp_incomplete:
                    rows.append(_row("ARP Gateway", "INCOMPLETO", "badge-error"))
                elif s.arp.gateway_mac:
                    rows.append(_row("ARP Gateway", s.arp.gateway_mac, "badge-ok"))

        if not rows:
            return "<p style='color:#94a3b8'>Dados de conectividade não disponíveis.</p>"

        return f"<table><tr><th>Teste</th><th>Resultado</th></tr>{''.join(rows)}</table>"

    def _html_ping_table(self, report: DiagnosticReport) -> str:
        """Gera tabela HTML de latências/jitter por alvo de ping."""
        if not report.synthetic_result or not report.synthetic_result.ping:
            return "<p style='color:#94a3b8'>Dados de ping não disponíveis.</p>"

        ping = report.synthetic_result.ping
        all_stats = []
        if ping.gateway:
            all_stats.append(("Gateway", ping.gateway))
        for s in ping.external_targets:
            all_stats.append((s.target, s))

        rows = []
        for label, stats in all_stats:
            loss_cls = "badge-error" if stats.packet_loss_pct >= 5 else (
                "badge-warn" if stats.packet_loss_pct > 0 else "badge-ok"
            )
            jitter_cls = "badge-warn" if (stats.jitter_ms or 0) > 30 else "badge-ok"
            lat_cls = "badge-warn" if (stats.avg_latency_ms or 0) > 100 else "badge-ok"

            rows.append(f"""<tr>
  <td>{label}<br><small style='color:#64748b'>{stats.target}</small></td>
  <td>{stats.packets_sent} / {stats.packets_received}</td>
  <td><span class='badge {loss_cls}'>{stats.packet_loss_pct:.0f}%</span></td>
  <td><span class='badge {lat_cls}'>{stats.avg_latency_ms or '—'}ms</span></td>
  <td>{stats.min_latency_ms or '—'}ms</td>
  <td>{stats.max_latency_ms or '—'}ms</td>
  <td><span class='badge {jitter_cls}'>{stats.jitter_ms or '—'}ms</span></td>
</tr>""")

        return f"""<table>
<tr>
  <th>Alvo</th>
  <th>Pacotes Env/Rec</th>
  <th>Perda</th>
  <th>Latência Média</th>
  <th>Mín</th>
  <th>Máx</th>
  <th>Jitter (σ)</th>
</tr>
{''.join(rows)}
</table>"""

    def _html_dns_table(self, report: DiagnosticReport) -> str:
        """Gera tabela HTML de tempos DNS por resolver."""
        if not report.synthetic_result or not report.synthetic_result.dns:
            return "<p style='color:#94a3b8'>Dados DNS não disponíveis.</p>"

        dns = report.synthetic_result.dns
        rows = []

        for q in dns.queries:
            if q.timed_out:
                status = "<span class='badge badge-error'>TIMEOUT</span>"
                rt = "—"
            elif q.resolved_ip is None:
                status = "<span class='badge badge-error'>FALHA</span>"
                rt = "—"
            else:
                color = "badge-warn" if (q.response_time_ms or 0) > 200 else "badge-ok"
                status = f"<span class='badge {color}'>OK</span>"
                rt = f"{q.response_time_ms}ms"

            fastest_tag = " ⭐" if q.resolver_ip == dns.fastest_resolver_ip else ""
            rows.append(f"""<tr>
  <td>{q.resolver_ip}{fastest_tag}</td>
  <td>{q.queried_hostname}</td>
  <td>{status}</td>
  <td>{rt}</td>
  <td style='color:#64748b;font-family:monospace;font-size:12px'>{q.resolved_ip or (q.error or '—')}</td>
</tr>""")

        avg_str = f"{dns.avg_response_ms}ms" if dns.avg_response_ms else "—"
        footer = f"<p style='margin-top:12px;color:#94a3b8;font-size:12px'>⭐ Resolver mais rápido &nbsp;|&nbsp; Média: {avg_str}</p>"

        return f"""<table>
<tr>
  <th>Resolver</th>
  <th>Domínio</th>
  <th>Status</th>
  <th>Tempo</th>
  <th>IP Resolvido / Erro</th>
</tr>
{''.join(rows)}
</table>{footer}"""

    def _html_tcp_section(self, report: DiagnosticReport) -> str:
        """Gera seção de TCP handshake."""
        if not report.synthetic_result or not report.synthetic_result.tcp:
            return "<p style='color:#94a3b8'>Dados TCP não disponíveis.</p>"

        tcp = report.synthetic_result.tcp
        if tcp.success:
            color = "#f59e0b" if (tcp.handshake_time_ms or 0) > 300 else "#22c55e"
            status_html = f"<span class='badge badge-ok'>CONECTADO</span>"
            time_html = f"<span style='color:{color};font-weight:700'>{tcp.handshake_time_ms}ms</span>"
        else:
            status_html = "<span class='badge badge-error'>FALHA</span>"
            time_html = "—"

        return f"""<div class="kv-grid">
  <span class="kv-key">Host</span><span class="kv-val">{tcp.target_host}</span>
  <span class="kv-key">IP Resolvido</span><span class="kv-val">{tcp.target_ip or '—'}</span>
  <span class="kv-key">Porta</span><span class="kv-val">{tcp.port}</span>
  <span class="kv-key">Status</span><span class="kv-val">{status_html}</span>
  <span class="kv-key">Tempo de Handshake</span><span class="kv-val">{time_html}</span>
  {f'<span class="kv-key">Erro</span><span class="kv-val" style="color:#fca5a5">{tcp.error}</span>' if tcp.error else ''}
</div>"""

    def _html_arp_section(self, report: DiagnosticReport) -> str:
        """Gera seção ARP / gateway."""
        if not report.synthetic_result or not report.synthetic_result.arp:
            return "<p style='color:#94a3b8'>Dados ARP não disponíveis.</p>"

        arp = report.synthetic_result.arp
        mac_color = "#f59e0b" if arp.mac_changed else ("#ef4444" if arp.arp_incomplete else "#22c55e")
        mac_note = " ⚠️ MAC ALTERADO" if arp.mac_changed else (" ❌ INCOMPLETO" if arp.arp_incomplete else "")
        mac_changed_html = (
            "<span class='badge badge-warn'>SIM ⚠️</span>"
            if arp.mac_changed
            else "<span class='badge badge-ok'>Não</span>"
        )
        arp_incomplete_html = (
            "<span class='badge badge-error'>SIM</span>"
            if arp.arp_incomplete
            else "<span class='badge badge-ok'>Não</span>"
        )

        raw_html = ""
        if arp.raw_arp_table:
            raw_html = (
                "<details style='margin-top:12px'>"
                "<summary style='cursor:pointer;color:#94a3b8;font-size:12px'>Tabela ARP bruta</summary>"
                f"<pre>{_esc(arp.raw_arp_table[:3000])}</pre>"
                "</details>"
            )

        return (
            f'<div class="kv-grid">\n'
            f'  <span class="kv-key">Gateway IP</span>\n'
            f'  <span class="kv-val">{arp.gateway_ip or "—"}</span>\n'
            f'  <span class="kv-key">Gateway MAC</span>\n'
            f'  <span class="kv-val" style="color:{mac_color}">{arp.gateway_mac or "não resolvido"}{mac_note}</span>\n'
            f'  <span class="kv-key">MAC Alterado?</span>\n'
            f'  <span class="kv-val">{mac_changed_html}</span>\n'
            f'  <span class="kv-key">ARP Incomplete?</span>\n'
            f'  <span class="kv-val">{arp_incomplete_html}</span>\n'
            f'</div>\n{raw_html}'
        )

    def _html_interface_section(self, report: DiagnosticReport) -> str:
        """Gera seção de estado da interface Wi-Fi."""
        if not report.passive_result or not report.passive_result.interface_state:
            return "<p style='color:#94a3b8'>Estado da interface não disponível.</p>"

        iface = report.passive_result.interface_state
        rssi_color = "#22c55e" if (iface.rssi_dbm or -100) > -65 else (
            "#f59e0b" if (iface.rssi_dbm or -100) > -80 else "#ef4444"
        )

        return f"""<div class="kv-grid">
  <span class="kv-key">Interface</span><span class="kv-val">{_esc(iface.interface_name)}</span>
  <span class="kv-key">SSID</span><span class="kv-val">{_esc(iface.ssid)}</span>
  <span class="kv-key">BSSID</span><span class="kv-val" style="font-family:monospace">{_esc(iface.bssid)}</span>
  <span class="kv-key">Sinal (RSSI)</span>
  <span class="kv-val" style="color:{rssi_color};font-weight:700">{f'{iface.rssi_dbm} dBm' if iface.rssi_dbm is not None else '—'}</span>
  <span class="kv-key">Canal</span><span class="kv-val">{iface.channel or '—'}</span>
  <span class="kv-key">Banda</span><span class="kv-val">{iface.band or '—'}</span>
  <span class="kv-key">Autenticação</span><span class="kv-val">{iface.auth_type or '—'}</span>
  <span class="kv-key">Método de coleta</span><span class="kv-val" style="color:#64748b;font-size:12px">{iface.collection_method}</span>
</div>"""

    def _html_driver_section(self, report: DiagnosticReport) -> str:
        """Gera seção do driver Wi-Fi."""
        if not report.passive_result or not report.passive_result.driver_info:
            return "<p style='color:#94a3b8'>Informações de driver não disponíveis.</p>"

        driver = report.passive_result.driver_info
        outdated_html = ""
        if driver.is_outdated:
            outdated_html = " <span class='badge badge-warn' style='margin-left: 8px'>DESATUALIZADO (>2 anos)</span>"
        elif driver.is_outdated is False:
            outdated_html = " <span class='badge badge-ok' style='margin-left: 8px'>Atualizado</span>"
            
        return f"""<div class="kv-grid">
  <span class="kv-key">Adaptador</span><span class="kv-val">{_esc(driver.adapter_name)}</span>
  <span class="kv-key">Fabricante</span><span class="kv-val">{_esc(driver.provider)}</span>
  <span class="kv-key">Versão</span><span class="kv-val">{_esc(driver.version)}</span>
  <span class="kv-key">Data do Driver</span><span class="kv-val">{_esc(driver.date_str)}{outdated_html}</span>
  <span class="kv-key">Arquivo INF</span><span class="kv-val" style="font-family:monospace;font-size:12px">{_esc(driver.inf_file)}</span>
</div>"""

    def _html_correlated_events_section(self, report: DiagnosticReport) -> str:
        """Gera seção de eventos correlacionados (se houver)."""
        if not report.correlated_events:
            return ""

        rows = []
        for ce in report.correlated_events:
            sev_color = _SEVERITY_COLOR.get(ce.event.severity, "#94a3b8")
            rows.append(f"""<tr>
  <td style='font-family:monospace;font-size:12px;color:#94a3b8'>{ce.event.timestamp.strftime('%H:%M:%S')}</td>
  <td><span class='badge' style='background:{sev_color}22;color:{sev_color}'>{ce.event.severity.upper()}</span></td>
  <td>ID {ce.event.event_id}</td>
  <td style='font-size:12px'>{_esc(ce.event.description[:100])}</td>
  <td style='font-family:monospace;font-size:12px;color:#64748b'>{ce.related_metric}</td>
  <td style='color:#94a3b8'>±{ce.time_delta_s}s</td>
</tr>""")

        return f"""<details open>
  <summary>🔗 Eventos Correlacionados ({len(report.correlated_events)})</summary>
  <div class="section-body">
    <p style='color:#94a3b8;font-size:12px;margin-bottom:12px'>
      Eventos de rede do Módulo 1 correlacionados com anomalias do Módulo 2 (janela ±30s).
    </p>
    <table>
      <tr><th>Horário</th><th>Severidade</th><th>Event ID</th><th>Descrição</th><th>Métrica Relacionada</th><th>Δt</th></tr>
      {''.join(rows)}
    </table>
  </div>
</details>"""

    def _html_disconnect_history(self, report: DiagnosticReport) -> str:
        """Gera seção do histórico de desconexões."""
        if not report.passive_result or not report.passive_result.disconnect_history:
            return "<p style='color:#94a3b8'>Nenhuma desconexão registrada no período analisado.</p>"

        rows = []
        for disc in report.passive_result.disconnect_history:
            # Colorir de acordo com a causa
            if disc.cause.name == "USER_INITIATED" or disc.cause.name == "ROAMING":
                sev_color = "#3b82f6"  # Blue (normal)
            elif disc.cause.name == "AP_KICKED" or disc.cause.name == "AUTH_FAILURE":
                sev_color = "#ef4444"  # Red (falha externa/grave)
            else:
                sev_color = "#f59e0b"  # Yellow (sinal, timeout, driver)

            time_str = disc.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            downtime = f"{disc.downtime_seconds}s" if disc.downtime_seconds is not None else "<i>Não reconectou</i>"
            
            rows.append(f"""<tr>
  <td style='font-family:monospace;font-size:11px;white-space:nowrap;color:#94a3b8'>{time_str}</td>
  <td><strong>{_esc(disc.ssid) if disc.ssid else '?'}</strong><br><span style='font-size:10px;color:#64748b'>{_esc(disc.bssid) if disc.bssid else '?'}</span></td>
  <td><span class='badge' style='background:{sev_color}22;color:{sev_color}'>{disc.cause.value}</span></td>
  <td style='font-size:12px;color:#94a3b8'>{_esc(disc.raw_reason)}</td>
  <td style='font-family:monospace;font-size:12px'>{downtime}</td>
</tr>
<tr style='background-color: transparent;'>
  <td colspan="5" style='font-size:12px;color:#cbd5e1;padding-top:2px;padding-bottom:12px;border-top:none'>
    ↳ <em>{disc.cause_explanation}</em>
  </td>
</tr>""")

        return f"""<table>
<tr><th>Timestamp</th><th>Rede (SSID/BSSID)</th><th>Causa Principal</th><th>Motivo Bruto</th><th>Downtime</th></tr>
{''.join(rows)}
</table>
<p style='color:#64748b;font-size:11px;margin-top:8px'>
  A classificação de causas é derivada da análise avançada de códigos 802.11 e eventos do SO.
</p>"""

    def _html_raw_events(self, report: DiagnosticReport) -> str:
        """Gera seção de log de eventos brutos."""
        if not report.passive_result or not report.passive_result.events:
            return "<p style='color:#94a3b8'>Nenhum evento de rede coletado neste ciclo.</p>"

        source = getattr(report.passive_result, "events_source", "unknown")
        source_badge = f"<span class='badge' style='background:#3b82f622;color:#3b82f6;margin-left:8px'>Fonte: {source}</span>"

        rows = []
        for ev in report.passive_result.events[:50]:  # limitar a 50 eventos
            sev_color = _SEVERITY_COLOR.get(ev.severity, "#94a3b8")
            rows.append(f"""<tr>
  <td style='font-family:monospace;font-size:11px;white-space:nowrap;color:#94a3b8'>{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
  <td><span class='badge' style='background:{sev_color}22;color:{sev_color}'>{ev.event_id or '?'}</span></td>
  <td style='font-size:12px'>{_esc(ev.description[:150])}</td>
</tr>""")

        return f"""<p style='margin-bottom:12px'>Eventos brutos do adaptador Wi-Fi.{source_badge}</p>
<table>
<tr><th>Timestamp</th><th>Event ID</th><th>Descrição</th></tr>
{''.join(rows)}
</table>
<p style='color:#64748b;font-size:11px;margin-top:8px'>
  Mostrando até 50 eventos. Para eventos completos veja o arquivo ZIP.
</p>"""

    # -----------------------------------------------------------------------
    # TXT — Resumo executivo
    # -----------------------------------------------------------------------

    def _generate_txt_summary(self, report: DiagnosticReport) -> str:
        """
        Gera o resumo executivo em texto plano (≤10 linhas).

        Args:
            report: DiagnosticReport com todos os dados.

        Returns:
            String de texto plano do resumo.
        """
        lines: list[str] = []
        ts = report.timestamp.strftime("%d/%m/%Y %H:%M:%S UTC")
        platform_str = report.platform.os_version if report.platform else "Desconhecido"

        lines.append("=" * 58)
        lines.append("  NetDiag Agent — Resumo de Diagnóstico")
        lines.append("=" * 58)
        lines.append(f"  Data/Hora  : {ts}")
        lines.append(f"  Plataforma : {platform_str}")
        lines.append(f"  Veredito   : {report.verdict.value}")
        lines.append(f"  Nota       : {report.health_score}/100 ({report.health_grade.value})")
        lines.append(f"  Descrição  : {report.verdict_description[:80]}")

        # Métricas-chave
        if report.synthetic_result:
            s = report.synthetic_result
            if s.ping and s.ping.gateway and s.ping.gateway.packets_received > 0:
                lines.append(
                    f"  Gateway    : {s.arp.gateway_ip if s.arp else '?'} — "
                    f"latência {s.ping.gateway.avg_latency_ms}ms, "
                    f"perda {s.ping.gateway.packet_loss_pct:.0f}%"
                )
            elif s.ping and s.ping.gateway:
                lines.append(f"  Gateway    : SEM RESPOSTA AO PING")

            if s.dns and s.dns.fastest_resolver_ip:
                lines.append(
                    f"  DNS        : OK via {s.dns.fastest_resolver_ip} "
                    f"({s.dns.avg_response_ms}ms média)"
                )
            elif s.dns:
                lines.append("  DNS        : FALHA em todos os resolvers")

            if s.tcp:
                if s.tcp.success:
                    lines.append(f"  TCP 443    : OK — {s.tcp.handshake_time_ms}ms handshake")
                else:
                    lines.append(f"  TCP 443    : FALHA — {s.tcp.error or 'sem resposta'}")

        if report.correlated_events:
            lines.append(
                f"  Eventos    : {len(report.correlated_events)} evento(s) correlacionado(s) "
                f"com anomalias detectadas"
            )

        if report.skipped_collections:
            lines.append(
                f"  AVISO      : {len(report.skipped_collections)} coleta(s) ignorada(s) "
                f"por falta de privilégio — execute como Admin para dados completos."
            )

        lines.append("=" * 58)
        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # ZIP — Artefatos brutos
    # -----------------------------------------------------------------------

    def _generate_zip(
        self,
        report: DiagnosticReport,
        output_dir: Path,
        timestamp_str: str,
    ) -> Path:
        """
        Cria um arquivo ZIP com os JSONs brutos de cada módulo.

        Arquivos no ZIP:
        - passive_collection.json
        - synthetic_tests.json
        - diagnostic_report.json

        Args:
            report: DiagnosticReport para serialização.
            output_dir: Diretório de saída.
            timestamp_str: String de timestamp para nomear o ZIP.

        Returns:
            Path do arquivo ZIP criado.
        """
        zip_path = output_dir / f"netdiag-report-{timestamp_str}.zip"

        def _to_dict(obj: Any) -> Any:
            if obj is None:
                return None
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "value"):  # enum
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):  # dataclass
                return {k: _to_dict(v) for k, v in obj.__dict__.items()}
            if isinstance(obj, list):
                return [_to_dict(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _to_dict(v) for k, v in obj.items()}
            return obj

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Módulo 1 — coleta passiva
            if report.passive_result:
                zf.writestr(
                    "passive_collection.json",
                    json.dumps(_to_dict(report.passive_result), indent=2, ensure_ascii=False),
                )

            # Módulo 2 — testes sintéticos
            if report.synthetic_result:
                zf.writestr(
                    "synthetic_tests.json",
                    json.dumps(_to_dict(report.synthetic_result), indent=2, ensure_ascii=False),
                )

            # Módulo 3 — relatório completo (sem dados brutos duplicados)
            report_summary = {
                "timestamp": report.timestamp.isoformat(),
                "verdict": report.verdict.value,
                "verdict_description": report.verdict_description,
                "health_score": report.health_score,
                "health_grade": report.health_grade.value,
                "correlated_events_count": len(report.correlated_events),
                "skipped_collections": report.skipped_collections,
                "errors": report.errors,
                "platform": _to_dict(report.platform),
            }
            zf.writestr(
                "diagnostic_report.json",
                json.dumps(report_summary, indent=2, ensure_ascii=False),
            )

        return zip_path
