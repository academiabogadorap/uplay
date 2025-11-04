#!/usr/bin/env bash
# ==========================================================
# 🔍 TEST DE FLUJO DE TORNEOS — MODO LECTURA (SEGURO)
# Autor: Víctor Manuel Bogado
# ==========================================================

BASE="http://127.0.0.1:5000"
COOKIEJAR=".cookies_admin.txt"
LOG=".test_torneos.log"
> "$LOG"

echo "==============================================" | tee -a "$LOG"
echo "  🔍 TEST DE FLUJO DE TORNEOS (LECTURA)"       | tee -a "$LOG"
echo "==============================================" | tee -a "$LOG"

# --- 1️⃣ LOGIN COMO ADMIN ---
ADMIN_NOMBRE="${ADMIN_NOMBRE:-ADMINISTRADOR}"
ADMIN_PIN="${ADMIN_PIN:-0000}"

echo "[1/7] 🔑 Iniciando sesión admin..." | tee -a "$LOG"
curl -s -c "$COOKIEJAR" -b "$COOKIEJAR" "$BASE/login" -o .login.html

# --- Mostrar primeras opciones para depurar ---
echo "🔎 Primeras opciones del selector:" | tee -a "$LOG"
grep -A1 "<option" .login.html | head -n 30 | tee -a "$LOG"

# --- Buscar coincidencia del nombre del admin (multilínea robusto) ---
if ! grep -Pzo "(?s)<option[^>]*>\s*${ADMIN_NOMBRE}\s*(—|<|$)" .login.html > /dev/null; then
  echo "⚠️ No se encontró al jugador '${ADMIN_NOMBRE}' en el formulario de login." | tee -a "$LOG"
  echo "💡 Verificá que exista en la base de datos con el nombre exacto o probá con otro (por ejemplo 'admin')." | tee -a "$LOG"
  exit 1
else
  echo "✅ Jugador '${ADMIN_NOMBRE}' detectado correctamente en el selector." | tee -a "$LOG"
fi

# --- Obtener CSRF Token ---
CSRF=$(grep -oP 'name="csrf_token"\s+value="([^"]+)"' .login.html | sed -E 's/.*value="([^"]+)".*/\1/')
if [ -z "$CSRF" ]; then
  echo "⚠️ No se pudo obtener el token CSRF del formulario de login." | tee -a "$LOG"
  exit 1
fi

# --- Realizar login con jugador_id=1 ---
curl -s -L -c "$COOKIEJAR" -b "$COOKIEJAR" \
  -H "Origin: ${BASE}" \
  -H "Referer: ${BASE}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "jugador_id=1" \
  --data-urlencode "pin=${ADMIN_PIN}" \
  --data-urlencode "csrf_token=${CSRF}" \
  -X POST "$BASE/login" -o .login_result.html

if grep -qi "panel" .login_result.html; then
  echo "✅ Login correcto" | tee -a "$LOG"
else
  echo "⚠️ Error de login (verificar PIN o CSRF)" | tee -a "$LOG"
  grep -E "error|alert|invalid|csrf" .login_result.html | head -n 10 | tee -a "$LOG"
fi

# --- 2️⃣ LISTADO DE TORNEOS ---
echo "[2/7] 📋 Listando torneos..." | tee -a "$LOG"
curl -s -b "$COOKIEJAR" "$BASE/admin/torneos" -o .torneos.html
grep -q "<table" .torneos.html && echo "✅ Tabla de torneos visible" | tee -a "$LOG" || echo "⚠️ No se encontró tabla de torneos" | tee -a "$LOG"

# --- 3️⃣ DETECTAR TORNEO RECIENTE ---
TORNEO_ID=$(grep -oP '/admin/torneos/\K[0-9]+' .torneos.html | tail -n1)
if [ -z "$TORNEO_ID" ]; then
  echo "⚠️ No se encontró ningún torneo activo" | tee -a "$LOG"
  exit 1
fi
echo "✅ Torneo detectado: ID=$TORNEO_ID" | tee -a "$LOG"

# --- 4️⃣ VISTA DEL TORNEO ---
echo "[3/7] 🔎 Verificando vista del torneo..." | tee -a "$LOG"
curl -s -b "$COOKIEJAR" "$BASE/admin/torneos/${TORNEO_ID}" -o .torneo_view.html
grep -q "Partidos y resultados" .torneo_view.html && echo "✅ Vista de torneo OK" | tee -a "$LOG" || echo "⚠️ Falla en vista torneo" | tee -a "$LOG"

# --- 5️⃣ ZONAS Y PARTIDOS ---
echo "[4/7] 🧱 Verificando zonas y tabla de partidos..." | tee -a "$LOG"
grep -q "Zonas del torneo" .torneo_view.html && echo "✅ Sección de zonas visible" | tee -a "$LOG" || echo "ℹ️ Aún no hay zonas generadas" | tee -a "$LOG"
grep -q "<table" .torneo_view.html && echo "✅ Tabla de partidos renderizada" | tee -a "$LOG" || echo "⚠️ No hay tabla de partidos" | tee -a "$LOG"

# --- 6️⃣ ENDPOINTS DE GENERACIÓN ---
echo "[5/7] 🧩 Verificando endpoints..." | tee -a "$LOG"
curl -s -I -b "$COOKIEJAR" "$BASE/admin/torneos/${TORNEO_ID}/generar_fixture" | grep -q "200" \
  && echo "✅ /generar_fixture responde" | tee -a "$LOG" || echo "⚠️ Error /generar_fixture (esperado si es POST)" | tee -a "$LOG"
curl -s -I -b "$COOKIEJAR" "$BASE/admin/torneos/${TORNEO_ID}/generar_segunda_ronda" | grep -q "200" \
  && echo "✅ /generar_segunda_ronda responde" | tee -a "$LOG" || echo "⚠️ Error /generar_segunda_ronda (esperado si es POST)" | tee -a "$LOG"

# --- 7️⃣ CHEQUEOS VISUALES ---
echo "[6/7] 🎨 Verificando estructura visual..." | tee -a "$LOG"
grep -q "hero-title" .torneo_view.html && echo "✅ Hero OK" | tee -a "$LOG" || echo "⚠️ Falta hero" | tee -a "$LOG"
grep -q "chip" .torneo_view.html && echo "✅ Chips visuales OK" | tee -a "$LOG" || echo "⚠️ Faltan chips" | tee -a "$LOG"
grep -q "btn btn-slim" .torneo_view.html && echo "✅ Botones renderizados" | tee -a "$LOG" || echo "⚠️ Faltan botones" | tee -a "$LOG"

# --- 8️⃣ FIN ---
echo "[7/7] ✅ Test completo — Revisión en .torneo_view.html" | tee -a "$LOG"
echo "📄 Log guardado en $LOG"
echo "=============================================="
