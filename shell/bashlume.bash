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

# Prefer data next to the path through which this loader was sourced. This
# keeps Nix profile/symlinkJoin compositions relocatable instead of pinning
# them to the otherwise empty core package's rules directory.
_bashlume_loader_file=${BASH_SOURCE[0]}
_bashlume_loader_dir=${_bashlume_loader_file%/*}
[[ $_bashlume_loader_dir == "$_bashlume_loader_file" ]] && _bashlume_loader_dir=.
_bashlume_loader_dir=$(
  builtin cd -- "$_bashlume_loader_dir" 2>/dev/null && builtin pwd -P
) || _bashlume_loader_dir=

_bashlume_system_rules=${_bashlume_loader_dir:+$_bashlume_loader_dir/rules}
if [[ ! -d $_bashlume_system_rules ]]; then
  _bashlume_system_rules=@BASHLUME_RULE_PATH@
fi
if [[ -d $_bashlume_system_rules ]]; then
  if [[ -n ${BASHLUME_RULE_PATH:-} ]]; then
    BASHLUME_RULE_PATH+=":$_bashlume_system_rules"
  else
    BASHLUME_RULE_PATH=$_bashlume_system_rules
  fi
fi
unset _bashlume_system_rules

_bashlume_system_keys=${_bashlume_loader_dir:+$_bashlume_loader_dir/trusted-keys}
if [[ ! -d $_bashlume_system_keys ]]; then
  _bashlume_system_keys=@BASHLUME_TRUSTED_KEY_PATH@
fi
if [[ -d $_bashlume_system_keys ]]; then
  if [[ -n ${BASHLUME_TRUSTED_KEY_PATHS:-} ]]; then
    BASHLUME_TRUSTED_KEY_PATHS+=":$_bashlume_system_keys"
  else
    BASHLUME_TRUSTED_KEY_PATHS=$_bashlume_system_keys
  fi
fi
unset _bashlume_system_keys _bashlume_loader_file _bashlume_loader_dir

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

# Keep dladdr-based lookup of the co-installed probe helper independent of
# later `cd` commands, even when BASHLUME_LIBRARY was supplied as a relative
# development path.
if [[ $_bashlume_library != /* ]]; then
  _bashlume_library_name=${_bashlume_library##*/}
  _bashlume_library_dir=${_bashlume_library%/*}
  [[ $_bashlume_library_dir == "$_bashlume_library" ]] && _bashlume_library_dir=.
  if _bashlume_library_dir=$(
    builtin cd -- "$_bashlume_library_dir" 2>/dev/null && builtin pwd -P
  ); then
    _bashlume_library=$_bashlume_library_dir/$_bashlume_library_name
  fi
  unset _bashlume_library_name _bashlume_library_dir
fi

if ! enable -f "$_bashlume_library" bashlume; then
  printf 'bashlume: failed to load %s; using native Readline\n' "$_bashlume_library" >&2
fi
unset _bashlume_library
