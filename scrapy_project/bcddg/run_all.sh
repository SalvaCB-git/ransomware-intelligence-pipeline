#!/bin/bash
# Lanza todos los spiders ACTIVOS en secuencia, uno detrás de otro.
#
# Útil para batch nocturno fuera del panel Flask. El panel Flask sigue siendo
# el lanzador recomendado (UI + STOP + log en vivo); este script existe como
# fallback si Flask está caído o se quiere automatizar vía cron.
#
# Lista actualizada en la auditoría 2026-05-19 contra el filesystem real.
# - Incluye los 14 spiders operativos (Tier 1 + Tier 2).
# - Excluye los 2 bloqueados por IP OCI (sophos_news, kaspersky_securelist):
#   timeout cierto, sólo gastarían minutos sin retorno.
# - NO incluye el ya-borrado bc_playwright_ransomware ni el inexistente
#   checkpoint_research_ransomware.

cd "$(dirname "$0")"
source ../venv/bin/activate

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="./outputs"
mkdir -p "$OUTDIR"

SPIDERS=(
    # Originales (febrero 2026)
    "bc_site_ransomware"
    "crowdstrike_blog_ransomware"
    "sentinelone_blog_ransomware"
    "cisco_talos_ransomware"
    "talos_blog_ransomware"
    "trendmicro_research_ransomware"
    # Tier 1 (sesión 2026-03-08)
    "cisa_stopransomware_ransomware"
    "dfir_report_ransomware"
    "elastic_security_ransomware"
    "huntress_ransomware"
    "microsoft_security_ransomware"
    # Tier 2 (sesión 2026-03-08)
    "red_canary_ransomware"
    "unit42_ransomware"
    "welivesecurity_ransomware"
)

TOTAL=${#SPIDERS[@]}
echo "======================================"
echo " INICIANDO SCRAPING — $TIMESTAMP"
echo " $TOTAL spiders en cola"
echo "======================================"

for i in "${!SPIDERS[@]}"; do
    SPIDER="${SPIDERS[$i]}"
    NUM=$((i+1))
    OUT="$OUTDIR/${SPIDER}_${TIMESTAMP}.csv"
    echo ""
    echo "[$NUM/$TOTAL] $SPIDER"
    echo "  → $OUT"
    scrapy crawl "$SPIDER" -o "$OUT" -s LOG_LEVEL=WARNING
    ARTS=$([ -f "$OUT" ] && tail -n +2 "$OUT" | wc -l || echo 0)
    echo "  ✓ $ARTS artículos encontrados"
    sleep 10
done

echo ""
echo "======================================"
echo " COMPLETADO"
echo " Resultados en: $OUTDIR/"
ls -lh "$OUTDIR/"*"$TIMESTAMP"* 2>/dev/null
echo "======================================"
