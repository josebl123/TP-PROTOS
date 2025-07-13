#!/usr/bin/env bash

# socks5_load_test.sh
# Prueba de carga escalonada a través de un proxy SOCKS5

PROXY='socks5h://127.0.0.1:1080'
URL="${1:-http://neverssl.com/}"    # Cambiar si querés otro endpoint
TIMEOUT=10
USERS_LIST=(10 50 100 200 300 400 500)

for NUM_USERS in "${USERS_LIST[@]}"; do
    echo -e "\n=============================="
    echo    "Iniciando test con $NUM_USERS usuarios"
    echo    "=============================="

    # Archivo temporal para resultados
    RESULT_FILE=$(mktemp)
    trap 'rm -f "$RESULT_FILE"' EXIT
    : > "$RESULT_FILE"

    for ((i=1; i<=NUM_USERS; i++)); do
        (
            result=$(curl --proxy "$PROXY" \
                          -o /dev/null \
                          --max-time "$TIMEOUT" \
                          --write-out 'HTTP_STATUS:%{http_code} TOTAL_TIME:%{time_total}s' \
                          -sS "$URL" 2>&1)

            exit_code=$?

            http_status=$(printf '%s' "$result" | sed -e 's/.*HTTP_STATUS:\([0-9]*\).*/\1/')
            total_time=$(printf '%s' "$result" | sed -e 's/.*TOTAL_TIME:\([^ ]*\).*/\1/')

            if [ $exit_code -ne 0 ]; then
                echo "User $i: ERROR ($result)"
                echo "ERROR" >> "$RESULT_FILE"
            elif [ "$http_status" -ge 200 ] && [ "$http_status" -lt 300 ]; then
                echo "User $i: SUCCESS ($http_status) in $total_time"
                echo "SUCCESS" >> "$RESULT_FILE"
            else
                echo "User $i: FAIL ($http_status) in $total_time"
                echo "FAIL" >> "$RESULT_FILE"
            fi
        ) &
    done

    wait

    success_count=$(grep -c '^SUCCESS$' "$RESULT_FILE")
    fail_count=$(grep -c '^FAIL$' "$RESULT_FILE")
    error_count=$(grep -c '^ERROR$' "$RESULT_FILE")

    echo
    echo "Resumen para $NUM_USERS usuarios:"
    echo "SUCCESS: $success_count"
    echo "FAIL:    $fail_count"
    echo "ERROR:   $error_count"
done
