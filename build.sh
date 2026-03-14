#!/bin/bash
set -e

if [ "$1" = "--baked" ]; then
    shift
    MODE=""
    HOST=""
    PORT=""
    KEY=""
    EXEC=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l) MODE="listen"; shift ;;
            -c) MODE="connect"; HOST="$2"; shift 2 ;;
            -p) PORT="$2"; shift 2 ;;
            -k) KEY="$2"; shift 2 ;;
            -e) EXEC="$2"; shift 2 ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done

    [ -z "$PORT" ] && { echo "Error: -p <port> required"; exit 1; }
    [ -z "$MODE" ] && { echo "Error: -l or -c <host> required"; exit 1; }
    [ -z "$KEY" ] && KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    GEN_ARGS="--mode $MODE --port $PORT --key $KEY"
    [ -n "$HOST" ] && GEN_ARGS="$GEN_ARGS --host $HOST"
    [ -n "$EXEC" ] && GEN_ARGS="$GEN_ARGS --exec $EXEC"

    python3 gen_baked.py $GEN_ARGS

    make baked

    echo ""
    echo "[*] Baked build complete. Binary takes no arguments."
    echo "[*] PSK: $KEY"
else
    KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "[*] Generated PSK: $KEY"
    echo ""

    make all

    echo ""
    echo "[*] Build complete."
    echo "[*] Usage (Linux):   ./build/grotto -l -p 4444 -k $KEY"
    echo "[*] Usage (Windows): build\\grotto.exe -c <ip> -p 4444 -k $KEY"
fi
