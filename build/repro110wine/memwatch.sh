#!/bin/bash
# Resource sampler for the cloud Wine jobs (REPRO-110). Prints one compact block per interval to the live step log and
# appends it to a file, until it is killed. Read-only: it never creates or touches the work tree.
#   $1  work root of build_full.py (deps/, moltenvk/, wine/ below it; may not exist yet)
#   $2  seconds between samples (default 60)
#   $3  log file (default $RUNNER_TEMP/memwatch.log)
work="${1:?work root}"
every="${2:-60}"
log="${3:-${RUNNER_TEMP:-/tmp}/memwatch.log}"
printf '== memwatch start %s ncpu=%s memsize_gb=%s\n' "$(date -u +%H:%M:%S)" "$(sysctl -n hw.ncpu)" \
  "$(( $(sysctl -n hw.memsize) / 1073741824 ))" | tee -a "$log"
while :; do
  {
    printf '== memwatch %s load=%s pressure=%s swap=[%s]\n' \
      "$(date -u +%H:%M:%S)" "$(sysctl -n vm.loadavg | tr -d '{}' | xargs)" \
      "$(sysctl -n kern.memorystatus_vm_pressure_level 2>/dev/null || echo ?)" \
      "$(sysctl -n vm.swapusage | tr -s ' ')"
    vm_stat | grep -E 'page size|Pages (free|active|inactive|wired down|occupied by compressor)|Pageouts|Swapouts' \
      | sed -E 's/Mach Virtual Memory Statistics: //; s/ +/ /g' | tr '\n' ';'
    printf '\n'
    ps -Ao rss=,pcpu=,etime=,comm= -m | head -4 | awk '{printf "  rss_mb=%d cpu=%s up=%s %s\n", $1/1024, $2, $3, $4}'
    newest=""
    for dir in "$work/wine/reports" "$work/moltenvk/reports" "$work/deps/reports"; do
      if [ -d "$dir" ]; then
        candidate="$(ls -t "$dir" 2>/dev/null | head -1)"
        if [ -n "$candidate" ] && { [ -z "$newest" ] || [ "$dir/$candidate" -nt "$newest" ]; }; then newest="$dir/$candidate"; fi
      fi
    done
    if [ -n "$newest" ] && [ -f "$newest" ]; then
      printf '  newest report: %s (%s bytes); tail: ' "${newest#$work/}" "$(stat -f %z "$newest")"
      tail -c 160 "$newest" | tr '\n\r' '  '
      printf '\n'
    fi
  } 2>&1 | tee -a "$log"
  sleep "$every"
done
