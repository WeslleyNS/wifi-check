#!/usr/bin/env bash
# =============================================================================
# NetDiag Agent — Bootstrap macOS / Linux
# Uso: curl -fsSL https://raw.githubusercontent.com/WeslleyNS/wifi-check/main/install.sh | bash
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       NetDiag Agent — Diagnóstico de Rede    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ---------------------------------------------------------------------------
# 1. Verificar Python 3
# ---------------------------------------------------------------------------
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(sys.version_info.major)")
        if [ "$ver" -ge 3 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "${RED}ERRO: Python 3 não encontrado.${NC}"
    echo "Instale em: https://www.python.org/downloads/"
    exit 1
fi

PY_VER=$($PYTHON --version 2>&1)
echo -e "${GREEN}✔ $PY_VER detectado${NC}"

# ---------------------------------------------------------------------------
# 2. Baixar o projeto
# ---------------------------------------------------------------------------
TMP_DIR=$(mktemp -d)
ZIP_PATH="$TMP_DIR/netdiag.zip"
PROJECT_DIR="$TMP_DIR/wifi-check-main"

echo -e "${YELLOW}⬇  Baixando NetDiag Agent do GitHub...${NC}"
curl -fsSL \
    "https://github.com/WeslleyNS/wifi-check/archive/refs/heads/main.zip" \
    -o "$ZIP_PATH"

unzip -q "$ZIP_PATH" -d "$TMP_DIR"
echo -e "${GREEN}✔ Download concluído${NC}"

# ---------------------------------------------------------------------------
# 3. Rodar diagnóstico
# ---------------------------------------------------------------------------
cd "$PROJECT_DIR"
echo ""
echo -e "${YELLOW}🔍 Iniciando diagnóstico de rede (30s)...${NC}"
echo -e "   (execute com sudo para dados mais completos de interface Wi-Fi)"
echo ""

OUTPUT=$($PYTHON run.py doctor --duration 30 2>&1 | tee /dev/stderr) || true

# ---------------------------------------------------------------------------
# 4. Extrair caminho do HTML da saída do tool
# ---------------------------------------------------------------------------
HTML_PATH=$(echo "$OUTPUT" | grep -o '\[HTML\].*' | sed 's/\[HTML\] Relatorio HTML : //' | xargs 2>/dev/null || true)

if [ -z "$HTML_PATH" ]; then
    # Fallback: procurar no Desktop
    DESKTOP="$HOME/Desktop"
    HTML_PATH=$(ls -t "$DESKTOP"/netdiag-report-*.html 2>/dev/null | head -1 || true)
fi

# ---------------------------------------------------------------------------
# 5. Abrir relatório no navegador
# ---------------------------------------------------------------------------
echo ""
if [ -n "$HTML_PATH" ] && [ -f "$HTML_PATH" ]; then
    echo -e "${GREEN}✔ Relatório gerado: $HTML_PATH${NC}"
    echo -e "${CYAN}🌐 Abrindo no navegador...${NC}"
    if command -v open &>/dev/null; then
        open "$HTML_PATH"          # macOS
    elif command -v xdg-open &>/dev/null; then
        xdg-open "$HTML_PATH"     # Linux
    else
        echo "Abra manualmente: $HTML_PATH"
    fi
else
    echo -e "${YELLOW}⚠  Relatório não encontrado automaticamente.${NC}"
    echo "   Verifique a saída acima para o caminho do arquivo HTML."
fi

echo ""
echo -e "${CYAN}Dica: para monitoramento contínuo, execute:${NC}"
echo -e "  $PYTHON run.py collect --daemon --interval 30"
echo ""

# Cleanup
rm -rf "$TMP_DIR"
