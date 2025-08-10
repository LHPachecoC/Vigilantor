#!/bin/bash

# ==============================================================================
#
#   Vigilantor - Script de Instalación Avanzado (v4)
#
#   Descripción:
#   Instala herramientas y la colección SecLists dentro del directorio del
#   proyecto para máxima portabilidad.
#
# ==============================================================================

# --- Configuración y Variables Globales ---
set -e  # El script se detendrá si un comando falla
# SecLists se instalará en el directorio actual
SECLISTS_DIR="SecLists"
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'

# --- Funciones de Ayuda (Helpers) ---
log_info() { echo -e "${C_BLUE}[*] $1${C_RESET}"; }
log_success() { echo -e "${C_GREEN}[+] $1${C_RESET}"; }
log_warning() { echo -e "${C_YELLOW}[!] $1${C_RESET}"; }
log_error() { echo -e "${C_RED}[-] $1${C_RESET}" >&2; exit 1; }
check_root() { if [ "$EUID" -ne 0 ]; then log_error "Este script debe ser ejecutado como root. Use 'sudo'."; fi; }
command_exists() { command -v "$1" &> /dev/null; }

# --- Funciones de Instalación ---

install_apt_dependencies() {
    log_info "Actualizando lista de paquetes e instalando dependencias base..."
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv git curl wget ruby-full build-essential snapd nmap nikto sqlmap wfuzz gobuster masscan whatweb
    log_success "Dependencias base instaladas."
}

install_python_tool_with_venv() {
    local tool_name="$1"
    local git_repo="$2"
    local requirements_file="$3"
    local executable_script="$4"
    local symlink_name="$5"
    local tool_dir="/opt/${tool_name}" # Las herramientas siguen en /opt para no saturar el dir del proyecto

    log_info "Instalando ${tool_name}..."
    if [ ! -d "${tool_dir}" ]; then
        git clone "${git_repo}" "${tool_dir}"
        python3 -m venv "${tool_dir}/venv"
        "${tool_dir}/venv/bin/pip" install -r "${tool_dir}/${requirements_file}"
        echo "#!/bin/bash" > "/usr/local/bin/${symlink_name}"
        echo "\"${tool_dir}/venv/bin/python\" \"${tool_dir}/${executable_script}\" \"\$@\"" >> "/usr/local/bin/${symlink_name}"
        chmod +x "/usr/local/bin/${symlink_name}"
        log_success "${tool_name} instalado y enlazado como '${symlink_name}'."
    else
        log_warning "${tool_name} ya parece estar instalado."
    fi
}

# --- SECCIÓN SEC-LISTS CORREGIDA ---
install_seclists() {
    log_info "Instalando la colección de wordlists SecLists..."
    # Clona en el directorio local si no existe
    if [ ! -d "${SECLISTS_DIR}" ]; then
        log_info "Clonando SecLists en ./${SECLISTS_DIR}/... (esto puede tardar)"
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "${SECLISTS_DIR}"
        log_success "SecLists instalado en el directorio del proyecto."
    else
        log_warning "El directorio SecLists ya existe."
    fi
}

install_ruby_tools() {
    log_info "Instalando herramientas de Ruby..."
    if ! command_exists wpscan; then gem install wpscan; log_success "WPScan instalado."; else log_warning "WPScan ya parece estar instalado."; fi
}

install_other_tools() {
    log_info "Instalando herramientas adicionales..."
    if ! command_exists amass; then snap install amass; log_success "OWASP Amass instalado."; else log_warning "Amass ya parece estar instalado."; fi
    if ! command_exists msfconsole; then
        log_info "Instalando Metasploit Framework..."
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
        chmod 755 /tmp/msfinstall && /tmp/msfinstall && rm /tmp/msfinstall
        log_success "Metasploit Framework instalado."
    else
        log_warning "Metasploit ya parece estar instalado."
    fi
}

final_summary() {
    log_info "--------------------------------------------------"
    log_success "¡Verificación del entorno completada!"
    log_info "SecLists está disponible en ./${SECLISTS_DIR}/"
    log_warning "Acciones manuales que podrían ser necesarias: Burp Suite, API Keys, etc."
    log_info "--------------------------------------------------"
}

# --- Función Principal (main) ---
main() {
    check_root
    log_info "Iniciando el script de instalación/verificación para Vigilantor."
    
    install_apt_dependencies
    install_seclists # <-- Se añade la instalación de SecLists
    install_python_tool_with_venv "Sublist3r" "https://github.com/aboul3la/Sublist3r.git" "requirements.txt" "sublist3r.py" "sublist3r"
    install_ruby_tools
    install_other_tools
    
    final_summary
}

# Ejecutar la función principal
main
