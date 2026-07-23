# BashLume loader. Source this file from an interactive Bash startup file.

[[ $- == *i* ]] || return 0

if (( BASH_VERSINFO[0] < 5 )); then
  printf 'bashlume: Bash 5.0 or newer is required; using native Readline\n' >&2
  return 0
fi

if [[ ${TERM:-dumb} == dumb || -n ${BASHLUME_DISABLE:-} ]]; then
  return 0
fi

if type -t bashlume >/dev/null 2>&1; then
  return 0
fi

_bashlume_library=${BASHLUME_LIBRARY:-@BASHLUME_LIBRARY@}
if [[ $_bashlume_library == @BASHLUME_LIBRARY@ ]]; then
  _bashlume_root=$(builtin cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
  if [[ -r $_bashlume_root/result/lib/bash/libbashlume.so ]]; then
    _bashlume_library=$_bashlume_root/result/lib/bash/libbashlume.so
  elif [[ -r $_bashlume_root/target/release/libbashlume.so ]]; then
    _bashlume_library=$_bashlume_root/target/release/libbashlume.so
  fi
  unset _bashlume_root
fi

if [[ ! -r $_bashlume_library ]]; then
  printf 'bashlume: library not found at %s; using native Readline\n' "$_bashlume_library" >&2
  unset _bashlume_library
  return 0
fi

if ! enable -f "$_bashlume_library" bashlume; then
  printf 'bashlume: failed to load %s; using native Readline\n' "$_bashlume_library" >&2
fi
unset _bashlume_library
