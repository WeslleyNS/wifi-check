<div align="center">

# 🔍 NetDiag Agent

**Diagnóstico automático de rede Wi-Fi em uma linha de comando**

Detecta desconexões, lentidão, falhas de DNS e driver desatualizado.  
Gera um relatório HTML visual que você abre no navegador e entende na hora.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?logo=windows&logoColor=white)](https://github.com/WeslleyNS/wifi-check)
[![macOS](https://img.shields.io/badge/macOS-12%2B-000000?logo=apple&logoColor=white)](https://github.com/WeslleyNS/wifi-check)
[![Sem dependências](https://img.shields.io/badge/deps-nenhuma-success)](https://github.com/WeslleyNS/wifi-check)

</div>

---

## ⚡ Execute agora — uma linha no terminal

> Não precisa instalar nada. Só precisa de Python 3.10+ já instalado.

### 🪟 Windows — PowerShell

```powershell
iwr -useb https://raw.githubusercontent.com/WeslleyNS/wifi-check/main/install.ps1 | iex
```

### 🍎 macOS — Terminal

```bash
curl -fsSL https://raw.githubusercontent.com/WeslleyNS/wifi-check/main/install.sh | bash
```

> **O que acontece ao rodar o comando acima?**
> 1. Baixa o código do GitHub para uma pasta temporária
> 2. Executa o diagnóstico de rede por 30 segundos
> 3. Abre o relatório HTML automaticamente no seu navegador
> 4. Todos os arquivos ficam salvos em **`Desktop/NetDiag-Logs/`**
> 5. A pasta temporária é apagada

---

## 🔒 Segurança e privacidade

| O que o NetDiag FAZ | O que o NetDiag NÃO FAZ |
|---|---|
| ✅ Faz ping em `8.8.8.8` e `1.1.1.1` para testar WAN | ❌ Nunca envia seus dados para nenhum servidor |
| ✅ Testa conexão TCP na porta 443 do `google.com` | ❌ Não captura senhas Wi-Fi salvas |
| ✅ Lê logs de rede locais do sistema | ❌ Não acessa arquivos pessoais |
| ✅ Salva relatórios apenas no seu Desktop | ❌ Não instala nenhum serviço ou daemon |
| ✅ Roda e termina — sem processos em segundo plano | ❌ Não requer cadastro ou conta |

---

## 📊 O que ele analisa

O NetDiag roda **3 módulos em paralelo** e cruza os resultados:

```
┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
│     Módulo 1            │   │     Módulo 2            │   │     Módulo 3            │
│  Coleta Passiva         │   │  Testes Sintéticos      │   │  Motor de Decisão       │
│                         │   │                         │   │                         │
│  • Estado da interface  │   │  • ARP — gateway L2     │   │  • Veredito automático  │
│    (SSID, BSSID, RSSI,  │   │  • Ping — gateway e     │   │  • Nota de saúde 0-100  │
│     canal, banda)       │   │    alvos externos       │   │  • Correlação causa-    │
│  • Driver Wi-Fi         │   │  • DNS raw (UDP)        │   │    efeito               │
│    (versão + data)      │   │  • TCP handshake 443    │   │  • Histórico de         │
│  • Histórico de         │   │                         │   │    desconexões          │
│    desconexões          │   │                         │   │                         │
└─────────────────────────┘   └─────────────────────────┘   └─────────────────────────┘
```

### Onde o diagnóstico vai te ajudar

| Sintoma relatado | O que o NetDiag detecta |
|---|---|
| "A internet cai de vez em quando" | Histórico de desconexões com hora, SSID e causa |
| "Fica lento às vezes" | Jitter alto (>30ms) e perda de pacotes >2% |
| "Abre alguns sites, outros não" | Falha específica de DNS ou bloqueio de TCP 443 |
| "Conectado no Wi-Fi mas sem internet" | Gateway acessível, WAN sem resposta → roteador/ISP |
| "Totalmente sem acesso" | Falha L2 — problema no adaptador ou no AP |
| "Driver nunca atualizado" | Data do driver + flag de desatualizado (>2 anos) |

---

## 🗂️ Arquivos gerados

Todos os arquivos ficam em **`Desktop/NetDiag-Logs/`** — basta compactar e enviar para análise:

```
Desktop/
└── NetDiag-Logs/
    ├── netdiag-report-20241128-143000.html   ← Abre no navegador, visual completo
    ├── netdiag-report-20241128-143000.txt    ← Resumo em texto, cole no chamado
    ├── netdiag-report-20241128-143000.zip    ← JSONs brutos de cada módulo
    └── netdiag-collect.jsonl                 ← Monitoramento contínuo (modo daemon)
```

### O que ler no relatório HTML

| Seção | O que significa |
|---|---|
| **Nota de saúde (círculo no topo)** | 90–100 = ótimo, 70–89 = estável, <70 = problema |
| **Veredito** | Diagnóstico automático com causa identificada |
| **Driver Wi-Fi** | Versão instalada + alerta se estiver desatualizado (>2 anos) |
| **Interface Wi-Fi** | SSID, BSSID, RSSI (sinal), canal, banda (2.4/5/6 GHz) |
| **Latência e Jitter** | Gráfico de ping — picos indicam instabilidade |
| **DNS** | Tempo de resposta dos resolvers 8.8.8.8 e 1.1.1.1 |
| **Histórico de desconexões** | Hora, causa e tempo offline de cada queda |

---

## 🚨 Vereditos e o que fazer

| Veredito | Diagnóstico | Ação recomendada |
|---|---|---|
| `OK` | Rede saudável | Nenhuma |
| `NETWORK_INSTABILITY` | Jitter >30ms ou perda >2% | Trocar canal Wi-Fi ou banda (5 GHz) |
| `DNS_FAILURE` | DNS lento ou sem resposta | Configurar 8.8.8.8 / 1.1.1.1 no adaptador |
| `FIREWALL_BLOCK` | TCP 443 bloqueado ou lento | Verificar firewall corporativo ou proxy |
| `NO_WAN` | Gateway OK, internet sem resposta | Reiniciar roteador/modem |
| `L2_ISOLATION` | Ping ao gateway falha | Reconectar ao Wi-Fi ou reiniciar adaptador |

---

## 🖥️ Como usar manualmente (com Python instalado)

```bash
# Clonar o repositório
git clone https://github.com/WeslleyNS/wifi-check.git
cd wifi-check

# Diagnóstico one-shot (30 segundos)
python run.py doctor --duration 30

# Diagnóstico completo (60 segundos, padrão)
python run.py doctor

# Monitoramento contínuo — grava em Desktop/NetDiag-Logs/netdiag-collect.jsonl
python run.py collect --daemon

# Monitoramento com ciclo de 60s
python run.py collect --daemon --interval 60
```

### Com privilégios elevados (dados mais completos)

```powershell
# Windows — PowerShell como Administrador
python run.py doctor

# macOS — Terminal com sudo
sudo python3 run.py doctor
```

> Com privilégios elevados, o NetDiag acessa logs detalhados de evento WLAN (Windows)
> e dados mais precisos de interface via `wdutil` (macOS).

---

## 🔌 Requisitos

| Requisito | Detalhe |
|---|---|
| **Python 3.10+** | Apenas built-ins da biblioteca padrão — sem pip install |
| **Windows 10/11** | Testado em Windows 10 22H2 e Windows 11 23H2 |
| **macOS 12+** | Testado em macOS 13 Ventura e 14 Sonoma |
| **Conexão com internet** | Para os testes de ping e DNS externos |

---

## 🏗️ Arquitetura interna

```
run.py / netdiag doctor
        │
        ▼
   Orchestrator (asyncio)
        │
   asyncio.gather() ──────────────────────────────────────┐
        │                                                  │
        ▼                                                  ▼
   PassiveCollector                               SyntheticTester
   ├─ netsh wlan show interface (Windows)         ├─ ARP → gateway MAC
   ├─ netsh wlan show drivers → versão driver     ├─ Ping → gateway + 8.8.8.8 + 1.1.1.1
   ├─ wevtutil / PowerShell → eventos WLAN        ├─ DNS raw UDP → 8.8.8.8 / 1.1.1.1
   ├─ system_profiler (macOS)                     └─ TCP connect → google.com:443
   └─ log show (macOS)
        │                                                  │
        └──────────────────┬───────────────────────────────┘
                           ▼
                    DecisionEngine
                    ├─ Veredito hierárquico
                    ├─ Nota de saúde 0-100
                    └─ Correlação evento ↔ anomalia
                           │
                           ▼
                      ReportGenerator
                      ├─ HTML (visual, navegador)
                      ├─ TXT (resumo para chamado)
                      └─ ZIP (JSONs brutos)
```

---

## 📦 Empacotamento como executável (opcional)

Para distribuir sem precisar do Python instalado:

```bash
pip install pyinstaller

# Windows → gera dist/netdiag.exe
pyinstaller netdiag-windows.spec

# macOS → gera dist/netdiag (unix binary)
pyinstaller netdiag-macos.spec
```

> **macOS — aviso Gatekeeper:** execute `xattr -d com.apple.quarantine ./netdiag`
> antes do primeiro uso, ou abra pelo Finder → botão direito → **Abrir**.

---

## 🔧 Integração Zabbix (monitoramento corporativo)

O modo `collect --daemon` grava um JSONL rotativo que pode ser lido pelo agente Zabbix:

```ini
# zabbix_agent2.conf
UserParameter=netdiag.verdict,python3 -c "import json,pathlib; lines=[l for l in pathlib.Path(r'C:\Users\Public\Desktop\NetDiag-Logs\netdiag-collect.jsonl').read_text().splitlines() if l]; print(json.loads(lines[-1]).get('verdict','UNKNOWN'))"
UserParameter=netdiag.health_score,python3 -c "import json,pathlib; lines=[l for l in pathlib.Path(r'C:\Users\Public\Desktop\NetDiag-Logs\netdiag-collect.jsonl').read_text().splitlines() if l]; print(json.loads(lines[-1]).get('health_score',0))"
```

---

<div align="center">

Feito para facilitar o diagnóstico de rede no suporte técnico.  
Dúvidas ou sugestões → abra uma [issue](https://github.com/WeslleyNS/wifi-check/issues).

</div>
