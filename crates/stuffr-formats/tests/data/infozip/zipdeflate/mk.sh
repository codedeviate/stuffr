#!/bin/sh
# mk.sh ZIP CORPUS OUT: every case at every level, as a named archive
# (file mode) and, for the pipe cases, stdin to a pipe (pipe mode).
ZIP=$1; C=$2; O=$3
cd "$C" || exit 1
for n in empty one text10k random40k mixed-32767 mixed-32768 mixed-32769 mixed-65535 mixed-65536 mixed-65537 dict300k random2m zeros1m big3m; do
  for l in 1 2 3 4 5 6 7 8 9; do
    rm -f "$O/$n.file.$l.zip"
    "$ZIP" -X -q -$l "$O/$n.file.$l.zip" "$n" || echo "FAIL $n $l"
  done
done
for n in empty one random40k mixed-32769; do
  for l in 1 2 3 4 5 6 7 8 9; do
    cat "$n" | "$ZIP" -X -q -$l - - | cat > "$O/$n.pipe.$l.zip" || echo "FAIL pipe $n $l"
  done
done
