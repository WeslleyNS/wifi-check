# NetDiag Agent

Ferramenta multiplataforma (Windows 10/11 e macOS 12+) de diagnóstico e monitoramento contínuo de rede. Python 3.10+, apenas built-ins.

## Uso rápido

```bash
# Diagnóstico one-shot (~60s), gera relatório HTML + TXT + ZIP no Desktop
netdiag doctor

# Diagnóstico com duração personalizada
netdiag doctor --duration 120

# Monitoramento contínuo (ciclo de 30s), grava em netdiag-collect.jsonl
netdiag collect --daemon

# Monitoramento com ciclo de 60s e arquivo personalizado
netdiag collect --daemon --interval 60 --output-file /var/log/netdiag/collect.jsonl
```

## Estrutura do Projeto

```
Script wifi/
├── run.py                        # Entry-point (PyInstaller + execução direta)
├── setup.py                      # Metadados do pacote + entry_points
├── netdiag-windows.spec          # PyInstaller spec — Windows (.exe)
├── netdiag-macos.spec            # PyInstaller spec — macOS (unix binary)
├── README.md
└── netdiag/
    ├── __init__.py
    ├── main.py                   # CLI (argparse) + ponto de entrada
    ├── models.py                 # Dataclasses e enums compartilhados
    ├── orchestrator.py           # Orquestrador assíncrono (asyncio)
    ├── modules/
    │   ├── __init__.py
    │   ├── passive_collector.py  # Módulo 1 — coleta passiva (interface + logs)
    │   ├── synthetic_tester.py   # Módulo 2 — testes L2–L7 (ARP/ping/DNS/TCP)
    │   └── decision_engine.py    # Módulo 3 — veredito + nota de saúde
    ├── output/
    │   ├── __init__.py
    │   ├── report_generator.py   # Geração HTML + TXT + ZIP (modo doctor)
    │   └── jsonl_writer.py       # Escritor JSONL rotativo (modo collect)
    └── utils/
        ├── __init__.py
        └── platform.py           # Detecção de SO e privilégios
```

## Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│                      main.py (CLI)                      │
│              argparse → doctor | collect                │
└──────────────────────┬──────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │  orchestrator   │  asyncio.gather()
              └──┬───────────┬──┘
                 │           │
    ┌────────────▼──┐   ┌────▼──────────────┐
    │  Módulo 1     │   │  Módulo 2          │
    │  Passive      │   │  Synthetic         │
    │  Collector    │   │  Tester            │
    │               │   │                   │
    │ • netsh/wdutil│   │ • ARP (L2)        │
    │ • wevtutil/log│   │ • Ping (L3)       │
    └───────┬───────┘   │ • DNS raw (L4/7)  │
            │           │ • TCP 443 (L4)    │
            └─────┬─────┘                   │
                  │     └───────────────────┘
         ┌────────▼────────┐
         │    Módulo 3     │
         │  Decision       │
         │  Engine         │
         │                 │
         │ • Hierarquia    │
         │ • Nota 0-100   │
         │ • Correlação   │
         └────────┬────────┘
                  │
       ┌──────────▼──────────┐
       │      Output         │
       │                     │
       │ doctor → HTML+TXT+ZIP│
       │ collect → JSONL     │
       └─────────────────────┘
```

## Vereditos hierárquicos

| Código | Condição | Nota de saúde |
|---|---|---|
| `L2_ISOLATION` | Ping ao gateway falha | 0–19 |
| `NO_WAN` | Gateway OK, externo falha | 20–39 |
| `DNS_FAILURE` | DNS > 500ms ou falha | 40–59 |
| `FIREWALL_BLOCK` | TCP 443 falha ou > 1s | 50–69 |
| `NETWORK_INSTABILITY` | Jitter > 30ms ou perda > 2% | 70–89 |
| `OK` | Tudo dentro dos limiares | 90–100 |

## Privilégios

O NetDiag Agent **não exige** Administrador/root para rodar. Funcionalidades degradadas sem elevação:

| Coleta | Sem privilégio | Com privilégio |
|---|---|---|
| Estado da interface Wi-Fi | ✅ netsh / system_profiler | ✅ netsh / wdutil |
| Logs de evento WLAN (Windows) | ❌ ignorado | ✅ wevtutil |
| wdutil info (macOS) | ❌ fallback para system_profiler | ✅ completo |

## Integração Zabbix (pull passivo)

Configure em `zabbix_agent2.conf`:

```ini
# Último veredito
UserParameter=netdiag.verdict,tail -1 C:\netdiag\collect.jsonl | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('verdict','UNKNOWN'))"

# Nota de saúde (0-100)
UserParameter=netdiag.health_score,tail -1 C:\netdiag\collect.jsonl | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('health_score',0))"
```

## Empacotamento (PyInstaller)

> **Nota:** O código precisa estar funcional antes de empacotar.

```bash
pip install pyinstaller

# Windows (gera dist/netdiag.exe)
pyinstaller netdiag-windows.spec

# macOS (gera dist/netdiag)
pyinstaller netdiag-macos.spec
```

### aviso Gatekeeper (macOS)

O binário não é assinado por padrão. Antes do primeiro uso:

```bash
xattr -d com.apple.quarantine ./netdiag
```

Ou: Finder → clique direito no binário → **Abrir** → **Abrir mesmo assim**.

## Dependências

- **Python 3.10+** (built-ins apenas)
- **psutil** *(opcional)* — instalar apenas se necessário para métricas extras de interface
- **PyInstaller** *(build only)* — não é distribuído com o binário final

## Limitações (fora do escopo v1)

- Extração de senha de perfil Wi-Fi salvo (risco de segurança)
- MTU discovery
- Mapeamento de canais vizinhos (scan)
