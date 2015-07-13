function info {
    echo "[+] ${@}"
}

function error {
    echo "[E] ${@}"
    exit 1
}
