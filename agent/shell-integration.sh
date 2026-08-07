# WebTerm — integrare shell (OSC 133 „semantic prompts").
#
# Marchează în fluxul terminalului unde începe promptul (A), unde începe
# comanda tastată (B), unde începe execuția (C) și unde s-a terminat, cu exit
# code (D;<cod>). Cu ele, UI-ul poate: sări între comenzi, arăta care a eșuat,
# copia exact output-ul unei comenzi și afișa durata.
#
# Se sursează din ~/.bashrc / ~/.zshrc. Nu schimbă promptul vizual, nu execută
# nimic la fiecare comandă în afară de câteva printf-uri.
#
# tmux: secvențele din interiorul unui pane NU ajung la terminalul exterior
# decât „împachetate" în DCS passthrough, iar serverul tmux trebuie să accepte
# passthrough. Le facem pe amândouă aici, deci nu e nevoie de configurare.

# doar shell interactiv (scripturile nu au prompt)
case "$-" in
  *i*) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac

if [ -n "$TMUX" ]; then
  # -p (pane), NU -g (server): passthrough activat GLOBAL ar lăsa ORICE proces
  # din ORICE sesiune tmux să injecteze secvențe DCS necenzurate spre browser
  # (OSC 133 fals, OSC 52 clipboard). Pe pane, se limitează la sesiunea asta și
  # se curăță odată cu ea. tmux ≥3.3 acceptă -p pentru allow-passthrough.
  tmux set -p allow-passthrough on 2>/dev/null \
    || tmux set -g allow-passthrough on 2>/dev/null   # fallback tmux vechi
  # emitent generic: $1 = corpul OSC complet („133;A", „7;file://…"). Pe tmux
  # trebuie împachetat în DCS passthrough, cu ESC dublat în payload.
  _wt_emit() { printf '\033Ptmux;\033\033]%s\007\033\\' "$1"; }
else
  _wt_emit() { printf '\033]%s\007' "$1"; }
fi
_wt_osc() { _wt_emit "133;$1"; }
# OSC 7 = directorul curent (cwd), ca panoul de fișiere să urmărească `cd`-ul.
# Emis la fiecare prompt (în precmd), deci reflectă mereu unde ești. Host-ul e
# doar cosmetic (UI-ul ignoră partea de host și folosește doar calea).
_wt_cwd() { _wt_emit "7;file://${HOSTNAME:-${HOST:-}}${PWD}"; }

if [ -n "$BASH_VERSION" ]; then
  # D;<exit> + A (început de prompt) înaintea fiecărui prompt nou
  _wt_precmd() {
    local e=$?
    _wt_osc "D;$e"
    _wt_osc "A"
    _wt_cwd
    return $e
  }
  case "$PROMPT_COMMAND" in
    *_wt_precmd*) ;;
    *) PROMPT_COMMAND="_wt_precmd${PROMPT_COMMAND:+; $PROMPT_COMMAND}" ;;
  esac
  # E = textul EXACT al comenzii, trimis de shell. Sub tmux nu ne putem baza pe poziţia
  # cursorului la B: marcajele merg prin DCS passthrough şi ajung la terminal ÎNAINTEA
  # textului promptului (tmux le scoate out-of-band, iar conţinutul panoului îl repictează
  # separat cu poziţionări absolute). Clientul citea atunci de la începutul rândului, adică
  # promptul + comanda („root@host:~# ls" în loc de „ls") — vizibil în istoric şi în
  # „copiază comanda". Cu E, textul nu mai depinde de ce era pe ecran.
  _wt_cmdline() {
    local c
    c=$(HISTTIMEFORMAT='' history 1) || return 0
    c="${c#"${c%%[![:space:]]*}"}"     # spaţiile din faţă
    c="${c#*[0-9] }"                   # numărul din history
    c="${c#"${c%%[![:space:]]*}"}"
    c="${c//$'\033'/}"; c="${c//$'\a'/}"   # OSC-ul nu poate purta ESC/BEL
    c="${c//$'\n'/ }"
    [ -n "$c" ] && _wt_osc "E;$c"
  }
  # C = începutul execuției (PS0 se afișează după Enter, înainte de comandă).
  # Gardă ca la PS1/PROMPT_COMMAND: la re-sursare, fără ea PS0 acumula
  # $(_wt_osc C)$(_wt_osc C)… → markeri C dubli → model de comenzi corupt.
  case "$PS0" in
    *_wt_pre_exec*) ;;
    *) PS0='$(_wt_pre_exec)'"${PS0}" ;;
  esac
  _wt_pre_exec() { _wt_cmdline; _wt_osc "C"; }
  # B = sfârșitul promptului / începutul comenzii tastate.
  # NU e de-ajuns o singură dată, la sursare: dacă rc-ul reasignează PS1 mai jos (sau un
  # prompt dinamic — starship, powerline, oh-my-posh — îl reconstruiește la fiecare prompt),
  # markerul se pierde. Fără B, clientul nu ştie unde se termină promptul şi înghite promptul
  # în textul comenzii („root@host:~# frs" în loc de „frs") — văzut în producţie.
  # Deci îl re-aplicăm înainte de FIECARE prompt, idempotent, dintr-un hook pus la FINALUL
  # lui PROMPT_COMMAND (după eventualul constructor de prompt al utilizatorului).
  # ne mutăm la FINALUL lui PROMPT_COMMAND (string sau array), ca să rulăm după oricine.
  # Sintaxa de array e ascunsă în `eval`: fişierul trebuie să rămână PARSABIL de /bin/sh
  # (dash) — cine îl sursează dintr-un shell POSIX trebuie să iasă curat prin garda de
  # interactivitate, nu să primească „Syntax error" la parsare.
  _wt_relast() {
    case "$(declare -p PROMPT_COMMAND 2>/dev/null)" in
      "declare -a"*)
        eval 'local i; local -a rest=()
              for i in "${PROMPT_COMMAND[@]}"; do [ "$i" = "_wt_ps1_b" ] || rest+=("$i"); done
              rest+=(_wt_ps1_b); PROMPT_COMMAND=("${rest[@]}")' ;;
      *)
        # Scoatem DOAR propriul nume, cu separatorul lui, şi ne re-adăugăm la final.
        # NU împărţim şirul pe „;" şi nu-l reasamblăm: `;` apare des ÎNTRE GHILIMELE în
        # PROMPT_COMMAND-urile reale (`printf "\033]0;%s\007" "$PWD"` — titlul de terminal),
        # iar reasamblarea rescria codul utilizatorului (verificat: `]0;%s` devenea `]0; %s`;
        # cu un `case ... ;;` sau un program awk l-ar fi rupt de tot). Ştergerea ţintită nu
        # poate lăsa nici separatori goi, fiindcă separatorul pleacă odată cu numele.
        local p="$PROMPT_COMMAND"
        p="${p//_wt_ps1_b; /}"      # la început sau la mijloc
        p="${p//; _wt_ps1_b/}"      # la final
        p="${p//_wt_ps1_b/}"        # singur
        PROMPT_COMMAND="${p:+$p; }_wt_ps1_b" ;;
    esac
  }
  _wt_ps1_b() {
    case "$PS1" in
      *_wt_osc\ B*) ;;
      *)
        # PS1 nu mai are markerul: ori e primul prompt, ori cineva l-a reconstruit DUPĂ noi
        # (prompt dinamic). În ambele cazuri ne re-aşezăm la final şi re-aplicăm — la
        # promptul următor rulăm ultimii, deci markerul rezistă.
        _wt_relast
        PS1="${PS1}"'\[$(_wt_osc B)\]' ;;
    esac
  }
  _wt_ps1_b                                  # pentru primul prompt, înainte de orice hook
  case "$(declare -p PROMPT_COMMAND 2>/dev/null)" in
    *_wt_ps1_b*) ;;                          # deja adăugat (re-sursare)
    "declare -a"*)                           # bash ≥5.1 permite PROMPT_COMMAND ca ARRAY
      eval 'PROMPT_COMMAND+=(_wt_ps1_b)' ;;  # în eval: fişierul rămâne parsabil de /bin/sh
    *) PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }_wt_ps1_b" ;;
  esac

elif [ -n "$ZSH_VERSION" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null || true
  _wt_precmd() {
    local e=$?
    _wt_osc "D;$e"
    _wt_osc "A"
    _wt_cwd
  }
  # la zsh comanda vine gata în $1 (vezi de ce trimitem E: comentariul din ramura bash)
  _wt_preexec() {
    local c="${1//$'\033'/}"
    c="${c//$'\a'/}"; c="${c//$'\n'/ }"
    [ -n "$c" ] && _wt_osc "E;$c"
    _wt_osc "C"
  }
  # B (sfârșit de prompt) tot printr-un hook precmd, NU prin PS1: zsh nu
  # expandează $(...) în prompt fără `setopt PROMPT_SUBST` (off implicit), deci
  # un zsh „gol" ar afișa literal „%{$(_wt_osc B)%}". Emitem B la finalul lui
  # precmd (după A), înainte de afișarea promptului — semantic echivalent.
  _wt_precmd_b() { _wt_osc "B"; }
  if whence add-zsh-hook >/dev/null 2>&1; then
    add-zsh-hook precmd _wt_precmd
    add-zsh-hook precmd _wt_precmd_b
    add-zsh-hook preexec _wt_preexec
  fi
fi
