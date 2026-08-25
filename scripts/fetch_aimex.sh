#!/usr/bin/env bash
#
# fetch_aimex.sh -- download the archived AIM Express client and buddy-icon
# uploader from the Wayback Machine.
#
# Static URL lists. The id_ in each URL is what makes the archive return the
# ORIGINAL bytes instead of its rewritten viewer page -- omit it and every .swf
# comes back as HTML. The local path is whatever follows the build directory.
#
# Downloads are strictly SERIAL with a delay between every request. The Wayback
# Machine throttles by refusing connections outright (curl exit 7, not an HTTP
# 429) and stays angry for a while, so slow beats parallel.
#
# Usage:
#   ./fetch_aimex.sh                 # fetch anything missing under ./clients
#   ./fetch_aimex.sh -o somewhere    # write somewhere else
#   ./fetch_aimex.sh -d 5            # be extra polite
#   ./fetch_aimex.sh --force         # re-download everything

set -uo pipefail

EXPRESS_URLS=(
    "https://web.archive.org/web/20130905172104id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/AC_OETags.js"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/ConversationAssets.swf"
    "https://web.archive.org/web/20130905172110id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/OnlinePanel.swf"
    "https://web.archive.org/web/20150109230526id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/WidgetMain.html"
    "https://web.archive.org/web/20130905172106id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/WidgetMain.swf"
    "https://web.archive.org/web/20150115210119id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/_uac/adpage.html"
    "https://web.archive.org/web/20150426081851id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/babybunny.png"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/default_buddy_icon.png"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/default_imserv_icon.png"
    "https://web.archive.org/web/20130905172109id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/default_login_user_icon.png"
    "https://web.archive.org/web/20130905172109id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/progress_animation.swf"
    "https://web.archive.org/web/20150426081854id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/check.png"
    "https://web.archive.org/web/20150426081854id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/facebook_h.png"
    "https://web.archive.org/web/20150426081854id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/facebook_n.png"
    "https://web.archive.org/web/20150426081854id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/ls_h.png"
    "https://web.archive.org/web/20150426081854id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/ls_n.png"
    "https://web.archive.org/web/20150426081854id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/plus.png"
    "https://web.archive.org/web/20150426081855id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/twitter_h.png"
    "https://web.archive.org/web/20150426081854id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/twitter_n.png"
    "https://web.archive.org/web/20150426081855id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/youtube_h.png"
    "https://web.archive.org/web/20150426081855id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/youtube_n.png"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/all.gif"
    "https://web.archive.org/web/20150426081813id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/facebook.gif"
    "https://web.archive.org/web/20150426081813id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/lifestream.gif"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/location.gif"
    "https://web.archive.org/web/20150426081813id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/myspace.gif"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/photo.gif"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/status.gif"
    "https://web.archive.org/web/20150426081813id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/twitter.gif"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/video.gif"
    "https://web.archive.org/web/20100829133330id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/help/aim_or_fb.html"
    "https://web.archive.org/web/20130905172109id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/serviceicons/runningman.png"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/emoticons/GromitEmoticons.swf"
    "https://web.archive.org/web/20150426081812id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/norris.txt"
    "https://web.archive.org/web/20150115211959id_/http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/portal.php"
)

ICONUPLOADER_URLS=(
    "https://web.archive.org/web/20151127135337id_/http://o.aolcdn.com/aim/gromit/iconuploader/110128.1.5797/Main.html"
    "https://web.archive.org/web/20160126020222id_/http://o.aolcdn.com/aim/gromit/iconuploader/110128.1.5797/Main.swf"
    "https://web.archive.org/web/20120815104026id_/http://o.aolcdn.com/aim/gromit/iconuploader/110128.1.5797/redir.html"
    "https://web.archive.org/web/20160126020219id_/http://o.aolcdn.com/aim/gromit/iconuploader/110128.1.5797/swfobject.js"
)

OUTDIR="clients"
DELAY=2.5
MAX_RETRIES=5
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--outdir)      OUTDIR=$2; shift 2 ;;
        -d|--delay)       DELAY=$2; shift 2 ;;
        -r|--max-retries) MAX_RETRIES=$2; shift 2 ;;
        --force)          FORCE=1; shift ;;
        -h|--help)        sed -n '3,19p' "$0" | sed 's/^#\{0,1\} \{0,1\}//'; exit 0 ;;
        *)                echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/gromit.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT
trap 'echo; echo "interrupted -- re-run to resume (existing files are skipped)"; exit 130' INT

TOTAL=$(( ${#EXPRESS_URLS[@]} + ${#ICONUPLOADER_URLS[@]} ))
INDEX=0
REQUESTS=0
N_OK=0; N_SKIP=0; N_FAIL=0

bump_delay() {
    DELAY=$(awk -v d="$DELAY" 'BEGIN { v = d*1.5+1; printf "%.1f", (v > 30 ? 30 : v) }')
    echo "      $1 -- floor delay now ${DELAY}s"
}

# fetch URL OUTFILE LABEL
fetch() {
    local url=$1 out=$2 label=$3
    local attempt=0 code rc wait reason

    while :; do
        sleep "$DELAY"
        code=$(curl -sS --max-time 120 -D "$TMP/hdr" \
                    -o "$out.part" -w '%{http_code}' "$url" 2>/dev/null)
        rc=$?
        REQUESTS=$((REQUESTS+1))

        # -s: a zero-byte body is a failed capture, not a file.
        if [ "$rc" -eq 0 ] && [ "$code" = "200" ] && [ -s "$out.part" ]; then
            mv "$out.part" "$out"
            return 0
        fi
        rm -f "$out.part"

        wait=""
        if [ "$rc" -ne 0 ]; then
            reason="curl exit $rc"
            # 7 = couldn't connect: we tripped the throttle. Back off hard and
            # keep the floor raised for the rest of the run.
            case "$rc" in
                7|28|56) bump_delay "connection refused/timed out" ;;
            esac
        elif [ "$code" = "200" ]; then
            reason="empty response"
        else
            reason="HTTP $code"
            if [ "$code" = "404" ]; then
                echo "      !! 404 $label"
                return 1
            fi
            if [ "$code" = "429" ]; then
                bump_delay "rate limited"
                wait=$(awk 'tolower($1) ~ /^retry-after:/ {gsub(/\r/,""); print $2; exit}' "$TMP/hdr")
                case "$wait" in ''|*[!0-9]*) wait="" ;; esac
            fi
        fi

        if [ "$attempt" -ge "$MAX_RETRIES" ]; then
            echo "      !! $label: giving up after $((attempt+1)) attempts ($reason)"
            return 1
        fi
        [ -n "$wait" ] || wait=$(awk -v d="$DELAY" -v a="$attempt" \
            'BEGIN { v = d*(2^a)+2; print int(v > 120 ? 120 : v) }')
        attempt=$((attempt+1))
        echo "      $reason -- retry $attempt/$MAX_RETRIES in ${wait}s"
        sleep "$wait"
    done
}

# download SUBDIR BUILD_ID URL...
download() {
    local subdir=$1 build=$2
    shift 2
    local url rel dest
    for url in "$@"; do
        rel=${url##*/$build/}
        dest="$OUTDIR/$subdir/$rel"
        INDEX=$((INDEX+1))
        if [ "$FORCE" -eq 0 ] && [ -s "$dest" ]; then
            printf '[%2d/%d] skip  %s/%s\n' "$INDEX" "$TOTAL" "$subdir" "$rel"
            N_SKIP=$((N_SKIP+1))
            continue
        fi
        printf '[%2d/%d] get   %s/%s\n' "$INDEX" "$TOTAL" "$subdir" "$rel"
        mkdir -p "$(dirname "$dest")"
        if fetch "$url" "$dest" "$rel"; then
            echo "      $(wc -c < "$dest" | tr -d ' ') bytes"
            N_OK=$((N_OK+1))
        else
            N_FAIL=$((N_FAIL+1))
        fi
    done
}

download express      100820.5475.1.en-us "${EXPRESS_URLS[@]}"
download iconuploader 110128.1.5797       "${ICONUPLOADER_URLS[@]}"

printf '\n%s ok, %s skipped, %s failed  (%s requests)\n' \
    "$N_OK" "$N_SKIP" "$N_FAIL" "$REQUESTS"
exit 0
