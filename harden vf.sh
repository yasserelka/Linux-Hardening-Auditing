#!/bin/bash
# real implementation dial fork(), old versions it was just a simulation not the real one,

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

VERSION="4.0 (2026-05-14)"

# --- Variables ---
START_TIME=$(date +%s.%N)

print_header() {
    echo -e "${BLUE}=============================================================${NC}"
    echo -e "${BLUE}HARDEN - Linux Audit, Hardening & Remediation Suite${NC}"
    echo -e "${BLUE}Version: $VERSION${NC}"
    echo -e "${BLUE}=============================================================${NC}"
}

PROG_NAME="harden"
USER_NAME=$(whoami)
DATE_FMT="+%Y-%m-%d-%H-%M-%S"
VERBOSE=0
DRY_RUN=0
TARGET=""
AUTO_REMEDIATE=0
BASELINE_CMD=""
BANNER_GRAB=0
KERNEL_CVE=0
JSON_EXPORT=0

if [[ $EUID -eq 0 ]]; then
    LOG_DIR="/var/log/$PROG_NAME" #/var/log/harder.sh/history.log
else
    LOG_DIR="$HOME/.$PROG_NAME"
fi
LOG_FILE="$LOG_DIR/history.log"
BASELINE_DIR="$LOG_DIR/baseline"

mkdir -p "$BASELINE_DIR" 2>/dev/null

# Répertoire sécurisé pour les helpers C (protège contre les attaques symlink sur /tmp)
BUILD_DIR=$(mktemp -d /tmp/harden.XXXXXX 2>/dev/null) || { BUILD_DIR="/tmp/harden_$$"; mkdir -p "$BUILD_DIR"; }
trap 'rm -rf "$BUILD_DIR"' EXIT

CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0

# ==============================================================================
# LOGGING (flock sur toutes les écritures pour éviter les race conditions)
# ==============================================================================
log_info() {
    local TS
    TS=$(date "$DATE_FMT")
    local fork_tag=""
    [[ -n "${HARDEN_FORK_CHILD_PID:-}" ]] && fork_tag=" [FORK:PID=${HARDEN_FORK_CHILD_PID}]"
    local msg="${GREEN}$TS : $USER_NAME${fork_tag} : INFOS : $1${NC}"
    echo -e "$msg"
    
    # On n'incrémente pas le compteur si c'est un message de timing (pour garder un summary pertinent)
    if [[ "$2" != "no_count" ]]; then
        ((INFO_COUNT++))
    fi

    if [[ $DRY_RUN -eq 0 ]]; then
        { flock -x 200; echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"; } 200>"${LOG_FILE}.lock"
    fi
}

log_error() {
    local TS
    TS=$(date "$DATE_FMT")
    local fork_tag=""
    [[ -n "${HARDEN_FORK_CHILD_PID:-}" ]] && fork_tag=" [FORK:PID=${HARDEN_FORK_CHILD_PID}]"
    local msg="${RED}$TS : $USER_NAME${fork_tag} : ERROR : $1${NC}"
    echo -e "$msg" >&2
    if [[ $DRY_RUN -eq 0 ]]; then
        { flock -x 200; echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"; } 200>"${LOG_FILE}.lock"
    fi
}

log_warning() {
    local TS
    TS=$(date "$DATE_FMT")
    local fork_tag=""
    [[ -n "${HARDEN_FORK_CHILD_PID:-}" ]] && fork_tag=" [FORK:PID=${HARDEN_FORK_CHILD_PID}]"
    local msg="${YELLOW}$TS : $USER_NAME${fork_tag} : WARNING : $1${NC}"
    echo -e "$msg"
    ((WARNING_COUNT++))   # toujours incrémenté
    if [[ $DRY_RUN -eq 0 ]]; then
        { flock -x 200; echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"; } 200>"${LOG_FILE}.lock"
    fi
}

log_critical() {
    local TS
    TS=$(date "$DATE_FMT")
    local fork_tag=""
    [[ -n "${HARDEN_FORK_CHILD_PID:-}" ]] && fork_tag=" [FORK:PID=${HARDEN_FORK_CHILD_PID}]"
    local msg="${RED}$TS : $USER_NAME${fork_tag} : CRITICAL : $1${NC}"
    echo -e "$msg"
    ((CRITICAL_COUNT++))   # toujours incrémenté
    if [[ $DRY_RUN -eq 0 ]]; then
        { flock -x 200; echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"; } 200>"${LOG_FILE}.lock"
    fi
}

run_timed() {
    local cmd="$1"
    local start
    start=$(date +%s.%N)
    $cmd
    local end
    end=$(date +%s.%N)
    local duration
    duration=$(awk "BEGIN {print $end - $start}")
    log_info "Check $cmd finished in ${duration}s" "no_count"
}


# ==============================================================================
# HELP
# ==============================================================================
show_help() {
    cat <<EOF
HARDEN - Linux Audit, Hardening & Remediation Suite

Usage: $0 [OPTIONS] [<directory>]

OPTIONS:
  -h        Show help
  -c        Quick scan (7 essential checks) (requires <directory>)
  -C        Full scan (20 checks) (requires <directory>)
  -t        Thread mode (real POSIX threads via C helper)
  -s        Subshell mode
  -f        Fork mode — père scanne /rep1, fils scanne /rep2 (usage: -f /rep1 /rep2)
  -l DIR    Log directory
  -r        Restore defaults (root only)
  -n        Dry-run (no logs written)
  -V        Show version
  -v        Verbose

  -a        Auto‑remediation (apply fixes from last scan)
  -b store  Store baseline of critical files (hashes)
  -b check  Check baseline for unauthorised changes
  -B        Banner grab (ports 22,80,443)
  -k        Kernel vulnerability hints (offline)
  -j        JSON export of the log

PARAM:
  <directory>  Target directory (required for -c / -C / -t / -s)
  -f requires TWO directories: ./harden -f /rep1 /rep2

ERROR CODES:
  100 Invalid option
  101 Missing parameter
  102 Permission denied
  103 Log error
  104 Python not found
  105 C helper compilation failed

EXAMPLES:
  ./harden -c /home            # Quick scan on /home
  ./harden -C /                # Full system scan
  ./harden -t /home            # Thread mode (real pthreads)
  ./harden -s /home            # Subshell mode
  ./harden -f /home /tmp       # Fork mode (père→/home, fils→/tmp)
  ./harden -a                  # Apply fixes from last scan
  ./harden -b store            # Store baseline
  ./harden -b check            # Check drift
  ./harden -k                  # Kernel vulnerability hints
  ./harden -j                  # JSON export
  ./harden -B                  # Banner grab
  sudo ./harden -r             # Restore defaults
EOF
    # Pas de exit 0 ici : permet l'appel depuis error_exit() avec retour de code correct
}

error_exit() {
    local msg="$1"
    local code="${2:-1}"
    # Enregistrement dans le log (même comportement qu'avant)
    log_error "[Code ${code}] ${msg}"
    # Affichage explicite du code d'erreur sur stderr
    echo -e "${RED}[ERROR ${code}] ${msg}${NC}" >&2
    case "$code" in
        100) echo -e "${YELLOW}  → Code 100 : Option invalide${NC}" >&2 ;;
        101) echo -e "${YELLOW}  → Code 101 : Paramètre manquant ou répertoire cible invalide${NC}" >&2 ;;
        102) echo -e "${YELLOW}  → Code 102 : Permission refusée (root requis)${NC}" >&2 ;;
        103) echo -e "${YELLOW}  → Code 103 : Erreur de log (impossible de créer le répertoire)${NC}" >&2 ;;
        104) echo -e "${YELLOW}  → Code 104 : Python3 introuvable${NC}" >&2 ;;
        105) echo -e "${YELLOW}  → Code 105 : Compilation échouée (gcc absent ou erreur)${NC}" >&2 ;;
    esac
    show_help
    exit "$code"
}

require_root() {
    [[ $EUID -ne 0 ]] && error_exit "This operation requires root" 102
}

# ==============================================================================
# RESTORE
# ==============================================================================
restore_system() {
    require_root
    rm -rf "$LOG_DIR"
    echo "Restored defaults (logs cleared)."
    exit 0
}

# ==============================================================================
# BASELINE
# ==============================================================================
baseline_store() {
    echo -e "${CYAN}[*] Storing baseline of critical files...${NC}"
    local baseline_file="$BASELINE_DIR/files.sha256"
    > "$baseline_file"
    local files=(
        "/etc/passwd" "/etc/shadow" "/etc/sudoers"
        "/etc/crontab" "/etc/ssh/sshd_config"
    )
    find / -perm -4000 -type f 2>/dev/null | head -100 > "$baseline_file.tmp"
    while read -r file; do
        files+=("$file")
    done < "$baseline_file.tmp"
    rm -f "$baseline_file.tmp"

    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            sha256sum "$file" >> "$baseline_file"
            echo "  Stored: $file"
        fi
    done
    echo -e "${GREEN}[✓] Baseline saved to $baseline_file${NC}"
}

baseline_check() {
    local baseline_file="$BASELINE_DIR/files.sha256"
    if [[ ! -f "$baseline_file" ]]; then
        echo -e "${RED}[!] No baseline found. Run './harden -b store' first.${NC}"
        return 1
    fi
    echo -e "${CYAN}[*] Checking baseline...${NC}"
    local changed=0
    while read -r line; do
        local hash=$(echo "$line" | awk '{print $1}')
        local file=$(echo "$line" | awk '{print $2}')
        if [[ -f "$file" ]]; then
            local current=$(sha256sum "$file" | awk '{print $1}')
            if [[ "$hash" != "$current" ]]; then
                echo -e "${RED}[!] File changed: $file${NC}"
                log_warning "Baseline drift: $file changed"
                ((changed++))
            fi
        else
            echo -e "${YELLOW}[!] File missing: $file${NC}"
            log_warning "Baseline drift: $file missing"
            ((changed++))
        fi
    done < "$baseline_file"
    if [[ $changed -eq 0 ]]; then
        echo -e "${GREEN}[✓] No unauthorised changes detected.${NC}"
    else
        echo -e "${YELLOW}[*] $changed file(s) changed since baseline.${NC}"
    fi
}

# ==============================================================================
# AUTO-REMEDIATION
# ==============================================================================
auto_remediate() {
    if [[ ! -f "$LOG_FILE" ]]; then
        echo -e "${RED}[!] No log file found. Run a scan first.${NC}"
        exit 1
    fi
    echo -e "${CYAN}[*] Extracting remediation steps from $LOG_FILE...${NC}"
    local fixes
    fixes=$(grep -E "Fix:" "$LOG_FILE" | sed 's/.*Fix: //' | sort -u)
    if [[ -z "$fixes" ]]; then
        echo -e "${GREEN}[✓] No fixes to apply.${NC}"
        exit 0
    fi
    echo -e "${YELLOW}The following fixes will be applied:${NC}"
    echo "$fixes"
    read -p "Apply these fixes? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    local backup_dir="$LOG_DIR/backup_$(date +%s)"
    mkdir -p "$backup_dir"

    # CORRECTION SÉCURITÉ : suppression de eval (dangereux si log compromis)
    # On utilise une whitelist stricte : seuls chmod et chown sont autorisés
    # sur des cibles qui sont de vrais fichiers/répertoires existants.
    echo "$fixes" | while IFS= read -r cmd; do
        local action target_file mode_or_owner
        action=$(awk '{print $1}' <<< "$cmd")
        mode_or_owner=$(awk '{print $2}' <<< "$cmd")
        target_file=$(grep -oE '(/[^ ]+)+' <<< "$cmd" | head -1)

        # Rejet immédiat si la cible est vide (log corrompu ou commande mal formée)
        if [[ -z "$target_file" ]]; then
            log_error "Cannot parse target from Fix command (malformed): $cmd"
            continue
        fi

        # Binaires système protégés : jamais modifiés automatiquement
        local -a PROTECTED_BINS=(
            "/usr/bin/passwd" "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/newgrp"
            "/usr/bin/gpasswd" "/bin/ping" "/usr/bin/pkexec" "/sbin/unix_chkpwd"
        )
        local is_protected=0
        for protected in "${PROTECTED_BINS[@]}"; do
            [[ "$target_file" == "$protected" ]] && is_protected=1 && break
        done
        if [[ $is_protected -eq 1 ]]; then
            log_error "REFUSED: $target_file is a protected system binary (apply manually)"
            continue
        fi

        case "$action" in
            chmod)
                if [[ -n "$target_file" && ( -f "$target_file" || -d "$target_file" ) ]]\
                   && [[ "$mode_or_owner" =~ ^[0-7]{3,4}$|^[ugoa][-+][rwxst]$ ]]; then
                    [[ -f "$target_file" ]] && cp "$target_file" "$backup_dir/" && \
                        echo "Backed up $target_file"
                    echo "Executing: chmod $mode_or_owner $target_file"
                    chmod "$mode_or_owner" "$target_file" 2>/dev/null \
                        && log_info "Auto-remediation: $cmd" \
                        || log_error "Failed: $cmd"
                else
                    log_error "Rejected unsafe chmod command: $cmd"
                fi
                ;;
            chown)
                if [[ -n "$target_file" && ( -f "$target_file" || -d "$target_file" ) ]]\
                   && [[ "$mode_or_owner" =~ ^[a-z_][a-z0-9_-]*(:[a-z_][a-z0-9_-]*)?$ ]]; then
                    [[ -f "$target_file" ]] && cp "$target_file" "$backup_dir/" && \
                        echo "Backed up $target_file"
                    echo "Executing: chown $mode_or_owner $target_file"
                    chown "$mode_or_owner" "$target_file" 2>/dev/null \
                        && log_info "Auto-remediation: $cmd" \
                        || log_error "Failed: $cmd"
                else
                    log_error "Rejected unsafe chown command: $cmd"
                fi
                ;;
            passwd)
                # Interactif — ne peut pas être automatisé
                log_info "Skipping interactive command (run manually): $cmd"
                ;;
            *)
                # Toute autre commande est refusée par sécurité
                log_error "Rejected non-whitelisted command: $cmd"
                ;;
        esac
    done
    echo -e "${GREEN}[✓] Remediation completed. Backups stored in $backup_dir${NC}"
    echo "Run 'sudo ./harden -r' to restore defaults (including these changes)."
}

# ==============================================================================
# PYTHON HELPERS
# ==============================================================================
check_python() {
    if ! command -v python3 &>/dev/null; then
        error_exit "Python3 not found" 104
    fi
}

kernel_cve_check() {
    echo -e "${CYAN}[*] Checking for known kernel vulnerabilities...${NC}"
    local kernel=$(uname -r)
    echo "Kernel: $kernel"
    local found=0
    if [[ "$kernel" =~ ^2\.6\.[0-9]+$ ]] || [[ "$kernel" == 3.* ]] || [[ "$kernel" == 4.[0-7].* ]]; then
        echo "⚠️  Dirty Cow (CVE-2016-5195) – kernel before 4.8"
        found=1
    fi
    if [[ "$kernel" =~ ^5\.([8-9]|1[0-6])\.[0-9]+$ ]] || [[ "$kernel" == "5.16."* ]]; then
        echo "⚠️  Dirty Pipe (CVE-2022-0847) – kernel 5.8 – 5.16"
        found=1
    fi
    echo "ℹ️  PwnKit (CVE-2021-4034) affects most Linux systems pre‑2022 (check with 'pkexec --version')"
    found=1
    if [[ $found -eq 0 ]]; then
        echo "No well‑known kernel exploits matched this version."
    fi
}

json_export() {
    check_python
    local logfile="$LOG_FILE"
    if [[ ! -f "$logfile" ]]; then
        echo "No log file found at $logfile"
        exit 1
    fi
    python3 - <<EOF
import json, re
log_file = "$logfile"
ansi_strip = re.compile(r'\x1b\[[0-9;]*m')   # supprime les séquences ANSI résiduelles
entries = []
with open(log_file) as f:
    for line in f:
        clean = ansi_strip.sub('', line.strip())
        match = re.match(r'^(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}) : (\w+) : (INFOS|ERROR|WARNING|CRITICAL) : (.*)$', clean)
        if match:
            entries.append({
                "timestamp": match.group(1),
                "user": match.group(2),
                "severity": match.group(3),
                "message": match.group(4)
            })
print(json.dumps(entries, indent=2))
EOF
}

banner_grab() {
    check_python
    echo -e "${CYAN}[*] Grabbing banners from local ports 22,80,443...${NC}"
    python3 - <<'EOF'
import socket
ports = [22, 80, 443]
for port in ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(256).decode().strip().split('\n')[0]
        print(f"Port {port}: {banner}")
        s.close()
    except:
        print(f"Port {port}: closed or no banner")
EOF
}

# ==============================================================================
# C HELPERS (REAL FORK & REAL THREADS)
# ==============================================================================
compile_fork_helper() {
    local src="${BUILD_DIR}/fork_helper.c"
    local bin="${BUILD_DIR}/fork_helper"
    if [[ -x "$bin" ]]; then return 0; fi
    # Vérification de la présence de gcc avant compilation (code 105)
    if ! command -v gcc &>/dev/null; then
        error_exit "gcc not found – cannot compile fork_helper" 105
    fi
    cat > "$src" << 'CSRC'
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

/* Reçoit : argv[1]=script  argv[2]=_real_fork_target  argv[3]=TARGET
   Passe tous les arguments à execvp pour éviter les problèmes de quoting. */
int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: fork_helper <script> [args...]\n"); return 1; }
    pid_t pid = fork();
    if (pid == -1) { perror("fork"); return 1; }
    if (pid == 0) {
        execvp(argv[1], &argv[1]);   /* argv[1] = chemin script, &argv[1] = tableau nul-terminé */
        perror("execvp"); return 1;
    } else {
        /* On ne fait pas de waitpid() pour que le fils s'exécute en arrière-plan */
        printf("[PARENT] Le processus fils (PID %d) a été lancé en arrière-plan.\n", pid);
        return 0;
    }
}
CSRC
    gcc "$src" -o "$bin" 2>/dev/null
    if [[ ! -x "$bin" ]]; then error_exit "Failed to compile fork_helper.c" 105; fi
    return 0
}

compile_thread_helper() {
    local src="${BUILD_DIR}/thread_helper.c"
    local bin="${BUILD_DIR}/thread_helper"
    if [[ -x "$bin" ]]; then return 0; fi
    # Vérification de la présence de gcc avant compilation (code 105)
    if ! command -v gcc &>/dev/null; then
        error_exit "gcc not found – cannot compile thread_helper" 105
    fi
    # Thread helper accept 2 commandes distinctes pour un vrai découpage des tâches
    cat > "$src" << 'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

typedef struct { char *command; } thread_data_t;

void *run_command(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    system(data->command);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: thread_helper <cmd1> <cmd2>\n");
        return 1;
    }
    pthread_t threads[2];
    thread_data_t data[2];
    data[0].command = argv[1];   /* Thread 1 : checks 1-11 */
    data[1].command = argv[2];   /* Thread 2 : checks 12-20 */
    if (pthread_create(&threads[0], NULL, run_command, &data[0]) != 0) {
        perror("pthread_create t1"); return 1;
    }
    if (pthread_create(&threads[1], NULL, run_command, &data[1]) != 0) {
        perror("pthread_create t2"); return 1;
    }
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    return 0;
}
CSRC
    gcc "$src" -o "$bin" -lpthread 2>/dev/null
    if [[ ! -x "$bin" ]]; then error_exit "Failed to compile thread_helper.c (pthread required)" 105; fi
    return 0
}

# ==============================================================================
# SECURITY CHECKS (22 functions)
# ==============================================================================
section() { echo -e "\n${YELLOW}--- $1 ---${NC}"; }

check_suid() {
    echo -ne "${CYAN}[*] Checking SUID binaries...${NC}"
    # Binaires SUID légitimes connus --- pas signalés
    local -a SUID_WHITELIST=(
        "/usr/bin/passwd" "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/newgrp"
        "/usr/bin/gpasswd" "/usr/bin/chfn" "/usr/bin/chsh" "/usr/bin/pkexec"
        "/bin/mount" "/bin/umount" "/bin/ping" "/sbin/unix_chkpwd"
        "/usr/sbin/unix_chkpwd"
    )
    find "$TARGET" -perm -4000 -type f 2>/dev/null | while read -r f; do
        local is_known=0
        for known in "${SUID_WHITELIST[@]}"; do
            [[ "$f" == "$known" ]] && is_known=1 && break
        done
        if [[ $is_known -eq 0 ]]; then
            log_warning "Unknown SUID binary: $f"
            log_info "Fix: chmod -s $f"
        fi
    done
    echo -e "\r${GREEN}[✓] SUID check done${NC}"
}

check_suid_vulnerable() {
    echo -ne "${CYAN}[*] Checking vulnerable SUID binaries (GTFOBins)...${NC}"
    local vulnerable=("bash" "find" "vim" "pkexec" "mount" "umount" "chsh" "gdb" "python" "perl" "ruby" "npm" "php" "socat" "wget" "curl" "git")
    # Intentionnellement système-complet (find /) : les GTFOBins dangereux se trouvent
    # dans /usr/bin, /usr/sbin, etc. --- pas nécessairement dans $TARGET.
    # check_suid() couvre $TARGET pour les SUID inconnus.
    find / -perm -4000 -type f 2>/dev/null | while read -r binary; do
        for vuln in "${vulnerable[@]}"; do
            if [[ "$binary" == *"$vuln"* ]]; then
                log_critical "Vulnerable SUID binary: $binary (check GTFOBins)"
                log_info "Fix: chmod -s $binary"
            fi
        done
    done
    echo -e "\r${GREEN}[✓] Vulnerable SUID check done${NC}"
}

check_sudo() {
    echo -ne "${CYAN}[*] Checking sudo permissions...${NC}"
    # -n = non-interactive : évite le blocage si sudo demande un mot de passe
    if ! sudo -n -l 2>/dev/null | while read -r line; do
        log_info "sudo: $line"
    done; then
        log_warning "sudo requires a password or is not available for this user"
    fi
    echo -e "\r${GREEN}[✓] Sudo check done${NC}"
}

check_sudo_nopasswd() {
    echo -ne "${CYAN}[*] Checking passwordless sudo...${NC}"
    grep -r "NOPASSWD" /etc/sudoers* 2>/dev/null | while read -r line; do
        log_critical "Passwordless sudo rule: $line"
        log_info "Fix: Remove NOPASSWD or restrict commands"
    done
    echo -e "\r${GREEN}[✓] Passwordless sudo check done${NC}"
}

check_cron() {
    echo -ne "${CYAN}[*] Checking cron jobs...${NC}"
    crontab -l 2>/dev/null | grep -v "^#" | while read -r line; do
        log_warning "Cron: $line"
    done
    echo -e "\r${GREEN}[✓] Cron check done${NC}"
}

check_cron_paths() {
    echo -ne "${CYAN}[*] Checking cron PATH safety...${NC}"
    crontab -l 2>/dev/null | grep -v "^#" | grep -E "PATH=|^\s*\S" | while read -r line; do
        if [[ "$line" == *"PATH=."* ]]; then
            log_warning "Cron job with unsafe PATH: $line"
            log_info "Fix: Use absolute paths in cron"
        fi
    done
    echo -e "\r${GREEN}[✓] Cron PATH check done${NC}"
}

check_passwd() {
    echo -ne "${CYAN}[*] Checking /etc/passwd writable...${NC}"
    if [[ -w /etc/passwd ]]; then
        log_critical "/etc/passwd is writable"
        log_info "Fix: chmod 644 /etc/passwd"
    fi
    echo -e "\r${GREEN}[✓] /etc/passwd check done${NC}"
}

check_root_users() {
    echo -ne "${CYAN}[*] Checking users with UID 0...${NC}"
    grep ':0:' /etc/passwd | cut -d: -f1 | while read -r user; do
        if [[ "$user" != "root" ]]; then
            log_critical "Non-root user with UID 0: $user"
            log_info "Fix: Remove or disable user $user"
        fi
    done
    echo -e "\r${GREEN}[✓] UID 0 check done${NC}"
}

check_empty_passwords() {
    echo -ne "${CYAN}[*] Checking empty passwords...${NC}"
    # Vérification des permissions : /etc/shadow n'est lisible qu'en root
    if [[ ! -r /etc/shadow ]]; then
        log_warning "Cannot read /etc/shadow (root required) --- empty password check skipped"
        echo -e "\r${YELLOW}[!] Empty password check skipped (insufficient permissions)${NC}"
        return
    fi
    # Seuls les comptes avec hash VIDE (pas * ni !) sont vraiment sans mot de passe
    grep -v '^#' /etc/shadow | awk -F: '$2 == "" {print $1}' | while read -r user; do
        log_critical "User with truly empty password: $user"
        log_info "Fix: passwd $user"
    done
    echo -e "\r${GREEN}[✓] Empty password check done${NC}"
}

check_env() {
    echo -ne "${CYAN}[*] Checking environment variables...${NC}"
    [[ "$PATH" == *"."* ]] && log_critical "PATH contains '.'"
    [[ -n "$LD_PRELOAD" ]] && log_critical "LD_PRELOAD set"
    echo -e "\r${GREEN}[✓] Environment check done${NC}"
}

check_ssh() {
    echo -ne "${CYAN}[*] Checking exposed SSH keys...${NC}"
    find "$TARGET" -name "id_rsa" 2>/dev/null | while read -r key; do
        [[ -r "$key" ]] && log_critical "Exposed key: $key"
        log_info "Fix: chmod 600 $key"
    done
    echo -e "\r${GREEN}[✓] SSH key check done${NC}"
}

check_ssh_config() {
    echo -ne "${CYAN}[*] Checking SSH configuration...${NC}"
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
        log_critical "PermitRootLogin is enabled"
        log_info "Fix: Set PermitRootLogin no in /etc/ssh/sshd_config"
    fi
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        log_warning "PasswordAuthentication is enabled"
        log_info "Fix: Set PasswordAuthentication no in /etc/ssh/sshd_config"
    fi
    echo -e "\r${GREEN}[✓] SSH config check done${NC}"
}

check_permissions() {
    echo -ne "${CYAN}[*] Checking world-writable files...${NC}"
    find "$TARGET" -type f -perm -0002 2>/dev/null | while read -r f; do
        log_warning "Writable file: $f"
        log_info "Fix: chmod o-w $f"
    done
    echo -e "\r${GREEN}[✓] World-writable files check done${NC}"
}

check_world_writable_dirs() {
    echo -ne "${CYAN}[*] Checking world-writable system directories...${NC}"
    for dir in /tmp /var/tmp /dev/shm; do
        if [[ -d "$dir" ]]; then
            local perm
            perm=$(stat -c "%a" "$dir" 2>/dev/null)
            # /tmp, /var/tmp, /dev/shm doivent avoir EXACTEMENT 1777 (sticky bit + world-writable)
            # Toute autre permission est anormale et signalée
            if [[ -n "$perm" ]] && [[ "$perm" != "1777" ]]; then
                log_warning "$dir has unexpected permissions: $perm (expected 1777)"
                log_info "Fix: chmod 1777 $dir"
            fi
        fi
    done
    echo -e "\r${GREEN}[✓] World-writable dirs check done${NC}"
}

check_unowned_files() {
    echo -ne "${CYAN}[*] Checking unowned files...${NC}"
    # Correction: parenthèses obligatoires autour de -nouser -o -nogroup
    # Exclusion de /proc, /sys, /run pour éviter le bruit système
    find / \( -nouser -o -nogroup \) \
        ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" \
        2>/dev/null | head -50 | while read -r file; do
        log_warning "Unowned file: $file"
        log_info "Fix: chown root:root $file"
    done
    echo -e "\r${GREEN}[✓] Unowned files check done${NC}"
}

check_writable_binaries() {
    echo -ne "${CYAN}[*] Checking writable system binaries...${NC}"
    find /bin /sbin /usr/bin -writable -type f 2>/dev/null | while read -r binary; do
        log_critical "Writable system binary: $binary"
        log_info "Fix: chmod 755 $binary"
    done
    echo -e "\r${GREEN}[✓] Writable binaries check done${NC}"
}

check_tmp_mounts() {
    echo -ne "${CYAN}[*] Checking /tmp mount options...${NC}"
    # Correction: grep -q lit stdin, /tmp était interprété comme fichier par grep
    # Fix: filtrer d'abord la ligne /tmp dans la sortie de mount, puis tester chaque option
    local mount_line
    mount_line=$(mount | grep " /tmp ")
    local missing=""
    for opt in noexec nodev nosuid; do
        echo "$mount_line" | grep -qw "$opt" || missing="$missing $opt"
    done
    if [[ -n "$missing" ]]; then
        log_warning "/tmp is missing mount options:$missing"
        log_info "Fix: Add 'noexec,nodev,nosuid' to /etc/fstab for /tmp"
    fi
    echo -e "\r${GREEN}[✓] /tmp mount check done${NC}"
}

check_kernel_version() {
    echo -ne "${CYAN}[*] Checking kernel version...${NC}"
    local kernel=$(uname -r)
    log_info "Kernel version: $kernel"
    echo -e "\r${GREEN}[✓] Kernel version check done${NC}"
}

check_capabilities() {
    echo -ne "${CYAN}[*] Checking capabilities...${NC}"
    getcap -r / 2>/dev/null | while read -r line; do
        log_warning "Binary with capabilities: $line"
        log_info "Fix: setcap -r $(echo $line | cut -d' ' -f1)"
    done
    echo -e "\r${GREEN}[✓] Capabilities check done${NC}"
}

check_docker_socket() {
    echo -ne "${CYAN}[*] Checking Docker socket permissions...${NC}"
    if [ -e /var/run/docker.sock ]; then
        local perm=$(stat -c %a /var/run/docker.sock)
        if [ "$perm" != "660" ]; then
            log_critical "Docker socket has unsafe permissions: $perm"
            log_info "Fix: chmod 660 /var/run/docker.sock"
        fi
    fi
    echo -e "\r${GREEN}[✓] Docker socket check done${NC}"
}

# ==============================================================================
# SCAN MODES
# ==============================================================================

# --------------------------------------------------------------------------
# quick_scan : 7 checks essentiels --- invoque par -c
# Concéu pour un audit rapide sur le répertoire cible
# --------------------------------------------------------------------------
quick_scan() {
    print_header
    log_info "Starting QUICK scan on $TARGET (7 essential checks)"
    run_timed check_suid
    run_timed check_permissions
    run_timed check_ssh
    run_timed check_ssh_config
    log_info "Quick scan completed"
}


# --------------------------------------------------------------------------
# full_scan : 20 checks complets --- invoqué par -C, -s, -t, -f
# Audit exhaustif de l'ensemble des vecteurs de sécurité
# --------------------------------------------------------------------------
full_scan() {
    print_header
    log_info "Starting FULL scan on $TARGET (20 checks)"
    run_timed check_suid
    run_timed check_suid_vulnerable
    run_timed check_sudo
    run_timed check_sudo_nopasswd
    run_timed check_cron
    run_timed check_cron_paths
    run_timed check_passwd
    run_timed check_root_users
    run_timed check_empty_passwords
    run_timed check_env
    run_timed check_ssh
    run_timed check_ssh_config
    run_timed check_permissions
    run_timed check_world_writable_dirs
    run_timed check_unowned_files
    run_timed check_writable_binaries
    run_timed check_tmp_mounts
    run_timed check_kernel_version
    run_timed check_capabilities
    run_timed check_docker_socket
    log_info "Full scan completed"
}


# scan_all : alias vers full_scan (compatibilité interne, subshell, fork)
scan_all() {
    full_scan
}

subshell_mode() {
    print_header
    log_info "Running in SUBSHELL mode (subshell isolé)"
    ( full_scan )   # sous-shell isolé : environnement copié, non partagé
}

thread_mode() {
    print_header
    log_info "Running in THREAD mode (real POSIX threads via C helper)"
    if ! compile_thread_helper; then
        error_exit "Failed to compile thread helper" 105
    fi
    # Thread 1 = checks 1-11, Thread 2 = checks 12-20
    local cmd1="$0 _thread_part1 $TARGET"
    local cmd2="$0 _thread_part2 $TARGET"
    "${BUILD_DIR}/thread_helper" "$cmd1" "$cmd2"
}

fork_mode() {
    local dir1="$1"
    local dir2="$2"
    print_header
    log_info "[PARENT pid=$$] Fork mode démarré — père scanne: \"$dir1\" | fils scanne: \"$dir2\" (arrière-plan)"

    # --- FILS : scan du deuxième répertoire en arrière-plan (output redirigé vers /dev/null) ---
    # Le fils tourne silencieusement ; ses résultats sont enregistrés uniquement dans le log.
    (
        TARGET="$dir2"
        export HARDEN_FORK_CHILD_PID=$BASHPID
        log_info "[CHILD pid=$BASHPID] Démarrage du scan sur \"$dir2\" (arrière-plan, résultats dans le log)"
        full_scan  >/dev/null 2>&1   # silencieux : pas d'affichage dans le terminal
        log_info "[CHILD pid=$BASHPID] SUMMARY - Critical: $CRITICAL_COUNT, Warnings: $WARNING_COUNT, Info: $INFO_COUNT"
        log_info "[CHILD pid=$BASHPID] Scan terminé sur \"$dir2\""
    ) &
    local child_pid=$!
    disown "$child_pid" 2>/dev/null
    echo -e "${CYAN}[*] Fils lancé en arrière-plan (PID $child_pid) — résultats enregistrés dans : $LOG_FILE${NC}"

    # --- PÈRE : scan du premier répertoire (affiché normalement dans le terminal) ---
    TARGET="$dir1"
    log_info "[PARENT pid=$$] Démarrage du scan sur \"$dir1\""
    full_scan   # affichage normal dans le terminal
    log_info "[PARENT pid=$$] Scan terminé sur \"$dir1\""
    log_info "[PARENT pid=$$] SUMMARY - Critical: $CRITICAL_COUNT, Warnings: $WARNING_COUNT, Info: $INFO_COUNT"

    print_summary   # résumé affiché dans le terminal ET enregistré dans le log
    echo -e "\n${YELLOW}[*] Le fils (PID $child_pid) continue en arrière-plan. Consultez : $LOG_FILE${NC}"
}

# Special internal modes used by C helpers
# _real_fork_target : exécute le scan complet dans le processus fils (fork réel via C helper)
# N'utilise PAS exec : appel direct de full_scan pour pouvoir logguer début ET fin avec le PID.
if [[ "$1" == "_real_fork_target" ]]; then
    TARGET="$2"
    export HARDEN_FORK_CHILD_PID=$$   # PID du processus fils, transmis à toutes les fonctions log
    log_info "=== FORK child PID=$$ : démarrage du scan complet sur \"$TARGET\" ==="
    print_header
    full_scan
    log_info "=== FORK child PID=$$ : scan terminé sur \"$TARGET\" ==="
    print_summary
    exit 0
fi

# _thread_part1 : checks 1-11 (SUID, sudo, cron, passwd, env, SSH keys)
if [[ "$1" == "_thread_part1" ]]; then
    TARGET="$2"
    print_header
    log_info "[Thread 1] Starting checks 1-11 on $TARGET"
    run_timed check_suid
    run_timed check_suid_vulnerable
    run_timed check_sudo
    run_timed check_sudo_nopasswd
    run_timed check_cron
    run_timed check_cron_paths
    run_timed check_passwd
    run_timed check_root_users
    run_timed check_empty_passwords
    run_timed check_env
    run_timed check_ssh
    print_summary
    exit 0
fi

# _thread_part2 : checks 12-20 (SSH config, perms, dirs, files, mounts, kernel, caps, docker)
if [[ "$1" == "_thread_part2" ]]; then
    TARGET="$2"
    log_info "[Thread 2] Starting checks 12-20 on $TARGET"
    run_timed check_ssh_config
    run_timed check_permissions
    run_timed check_world_writable_dirs
    run_timed check_unowned_files
    run_timed check_writable_binaries
    run_timed check_tmp_mounts
    run_timed check_kernel_version
    run_timed check_capabilities
    run_timed check_docker_socket
    print_summary
    exit 0
fi

# ==============================================================================
# SUMMARY
# ==============================================================================
print_summary() {
    local end_time=$(date +%s.%N)
    local duration=$(awk "BEGIN {print $end_time - $START_TIME}")
    
    local summary_text="SUMMARY - Critical: $CRITICAL_COUNT, Warnings: $WARNING_COUNT, Info: $INFO_COUNT, Duration: ${duration}s"
    log_info "$summary_text"

    echo -e "\n${GREEN}=== SUMMARY ===${NC}"
    echo "Critical issues: $CRITICAL_COUNT"
    echo "Warnings: $WARNING_COUNT"
    echo "Info messages: $INFO_COUNT"
    echo "Total duration: ${duration}s"
    echo "Log saved to: $LOG_FILE"

    if [[ $CRITICAL_COUNT -gt 0 && -f "$LOG_FILE" ]]; then
        echo -e "\n${YELLOW}Top critical issues:${NC}"
        grep "CRITICAL" "$LOG_FILE" | tail -3 | while read -r line; do
            echo "  - $(echo "$line" | sed 's/.*CRITICAL : //')"
        done
    fi

    echo -e "\n${GREEN}Run 'sudo ./harden -a' to apply fixes.${NC}"
    echo -e "${GREEN}Run 'sudo ./harden -r' to restore defaults.${NC}"
}

# ==============================================================================
# MAIN
# ==============================================================================
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

# Note : _real_fork_target / _thread_part1 / _thread_part2 sont interceptés
# individuellement plus haut dans le script (lignes 839-863). Aucun filet
# supplémentaire n'est nécessaire ici (il causerait un exit 0 prématuré).

MODE=""
QUICK_SCAN=0

# Correction: suppression des espaces invalides dans la chaîne getopts
# Les espaces empêchaient la reconnaissance de -a, -B, -k, -j
while getopts "hcCtsfl:rnVvab:Bkj" opt; do
    case $opt in
        h) show_help; exit 0 ;;  # exit 0 explicite car show_help ne quitte plus seul
        c) MODE="SCAN"; QUICK_SCAN=1 ;;
        C) MODE="SCAN"; QUICK_SCAN=0 ;;
        t) MODE="THREAD" ;;
        s) MODE="SUBSHELL" ;;
        f) MODE="FORK" ;;
        l)
            LOG_DIR="$OPTARG"
            LOG_FILE="$LOG_DIR/history.log"
            BASELINE_DIR="$LOG_DIR/baseline"
            mkdir -p "$LOG_DIR" || error_exit "Cannot create log dir: $LOG_DIR" 103
            ;;
        r) restore_system ;;
        n) DRY_RUN=1 ;;
        V) echo "HARDEN version $VERSION"; exit 0 ;;
        v) VERBOSE=1 ;;
        a) AUTO_REMEDIATE=1 ;;
        b) BASELINE_CMD="$OPTARG" ;;
        B) BANNER_GRAB=1 ;;
        k) KERNEL_CVE=1 ;;
        j) JSON_EXPORT=1 ;;
        *) error_exit "Invalid option" 100 ;;
    esac
done
shift $((OPTIND-1))

# Standalone actions
if [[ $AUTO_REMEDIATE -eq 1 ]]; then
    auto_remediate
    exit 0
fi
if [[ -n "$BASELINE_CMD" ]]; then
    case "$BASELINE_CMD" in
        store) baseline_store; exit 0 ;;
        check) baseline_check; exit 0 ;;
        *) error_exit "Usage: -b {store|check}" 100 ;;
    esac
fi
if [[ $BANNER_GRAB -eq 1 ]]; then
    banner_grab
    exit 0
fi
if [[ $KERNEL_CVE -eq 1 ]]; then
    kernel_cve_check
    exit 0
fi
if [[ $JSON_EXPORT -eq 1 ]]; then
    json_export
    exit 0
fi

# Scan modes require a target directory
if [[ -z "$MODE" ]]; then
    error_exit "No scan mode selected (-c, -C, -t, -s, -f)" 100
fi

# Fork mode : deux répertoires obligatoires
if [[ "$MODE" == "FORK" ]]; then
    TARGET1="$1"
    TARGET2="$2"
    if [[ -z "$TARGET1" || -z "$TARGET2" ]]; then
        error_exit "Fork mode requires two directories: -f /rep1 /rep2" 101
    fi
    [[ ! -d "$TARGET1" ]] && error_exit "First target is not a directory: $TARGET1" 101
    [[ ! -d "$TARGET2" ]] && error_exit "Second target is not a directory: $TARGET2" 101
else
    TARGET="$1"
    if [[ -z "$TARGET" ]]; then
        error_exit "Target directory required" 101
    fi
    if [[ ! -d "$TARGET" ]]; then
        error_exit "Target is not a directory" 101
    fi
fi

if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p "$LOG_DIR" 2>/dev/null || error_exit "Cannot create log dir" 103
fi

case "$MODE" in
    SCAN)
        # -c = quick_scan (7 checks) --- -C = full_scan (20 checks)
        if [[ $QUICK_SCAN -eq 1 ]]; then
            quick_scan
        else
            full_scan
        fi
        if [[ $DRY_RUN -eq 0 ]]; then
            print_summary
        fi
        ;;
    THREAD)
        thread_mode
        # Le résumé est produit dans chaque thread enfant
        ;;
    SUBSHELL)
        subshell_mode
        if [[ $DRY_RUN -eq 0 ]]; then
            print_summary
        fi
        ;;
    FORK)
        fork_mode "$TARGET1" "$TARGET2"
        # Résumé affiché dans fork_mode() après wait
        ;;
esac

exit 0