#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.."&&pwd)"
apk="${1:-$root/apps/android/app/build/outputs/apk/debug/app-debug.apk}"
: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-}}"
: "${ANDROID_NDK_HOME:=$ANDROID_HOME/ndk/27.2.12479018}"
bt="$ANDROID_HOME/build-tools/35.0.0"
[[ -f "$apk" && -x "$bt/apksigner" && -x "$bt/zipalign" ]]||{ echo "APK and SDK build-tools 35.0.0 required" >&2;exit 1; }
"$bt/apksigner" verify --verbose --print-certs "$apk"
"$bt/zipalign" -c -P 16 4 "$apk"
python3 - "$apk" <<'PY'
import sys,zipfile,struct
with zipfile.ZipFile(sys.argv[1]) as z:
 names=[n for n in z.namelist() if n.startswith('lib/') and n.endswith('.so')]
 assert names,'no native libraries'
 assert {n.split('/')[1] for n in names}=={'arm64-v8a','x86_64'},names
 for n in names:
  b=z.read(n)
  assert b[:6]==b'\x7fELF\x02\x01',n
  machine=struct.unpack_from('<H',b,18)[0]
  assert machine==({'arm64-v8a':183,'x86_64':62}[n.split('/')[1]]),(n,machine)
  off=struct.unpack_from('<Q',b,32)[0];entsize,num=struct.unpack_from('<HH',b,54)
  assert entsize>=56 and off+entsize*num<=len(b)
  loads=0
  for i in range(num):
   typ,flags,offset,vaddr,paddr,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',b,off+i*entsize)
   if typ==1:
    loads+=1
    assert align>=16384 and (vaddr-offset)%16384==0,(n,hex(align),hex(vaddr),hex(offset))
  assert loads>0,n
  print('PASS: 16 KiB ELF LOAD alignment',n)
PY
"$bt/aapt" dump badging "$apk"|grep -E '^(package:|sdkVersion:|targetSdkVersion:|native-code:|launchable-activity:)'
sha256sum "$apk"
echo "PASS: signed APK, supported ABIs and static 16 KiB alignment. Device runtime is not validated."
