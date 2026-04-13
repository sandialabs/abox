export HTTP_PROXY="http://{{.Gateway}}:{{.HTTPPort}}"
export HTTPS_PROXY="http://{{.Gateway}}:{{.HTTPPort}}"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
export NO_PROXY="localhost,127.0.0.1,{{.Gateway}}"
export no_proxy="$NO_PROXY"
{{- if .CACert }}

# CA certificate for MITM proxy (tools that don't use system CA store)
# Detect location based on distro (Debian vs RHEL)
if [[ -f /usr/local/share/ca-certificates/abox-proxy-ca.crt ]]; then
    export SSL_CERT_FILE="/usr/local/share/ca-certificates/abox-proxy-ca.crt"
elif [[ -f /etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt ]]; then
    export SSL_CERT_FILE="/etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt"
fi
if [[ -n "$SSL_CERT_FILE" ]]; then
    export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"
    export CURL_CA_BUNDLE="$SSL_CERT_FILE"
    export NODE_EXTRA_CA_CERTS="$SSL_CERT_FILE"
    export GIT_SSL_CAINFO="$SSL_CERT_FILE"
    export PIP_CERT="$SSL_CERT_FILE"
fi
{{- end }}
