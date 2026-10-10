#!/usr/bin/env bash
#
# relay_subscription.sh
# ---------------------------------------------------------------------------
# 把"本机可拉、但 GitHub/Azure runner 直连拉不到"的住宅订阅，经 gist 中转
# 投喂给 epic-gamer.yml 的 PROXY_SUBSCRIPTION，并立即触发工作流。
#
# 背景（续6 已确诊）：
#   Azure runner 网络封锁订阅主机（如 huaikhwang.central-world.org），但
#   gist.githubusercontent.com 在 runner 上可达（run 37899495839 已证它能从
#   gist 加载 52 个家宽节点）。所以模式是：
#     本机 curl 订阅 -> 校验含 ss:// 节点 -> gh gist create
#     -> gh secret set PROXY_SUBSCRIPTION -> gh workflow run
#     -> 等"Set up local proxy bridge"步骤跑完 -> gh gist delete（关凭证窗口）
#
# 安全设计：
#   * 任何一步失败（拉取非 200 / 内容不是合法订阅 / gist 创建失败）都直接退出，
#     绝不留下半截的 gist 或错误秘钥——这正是之前 SIGTERM 那次踩的坑。
#   * gist 用完即删，缩小订阅凭证暴露窗口。
#
# 用法：
#   ./relay_subscription.sh <SUBSCRIPTION_URL> [NODE_FILTER]
#   NODE_FILTER 省略时沿用既有的 vars.PROXY_NODE_FILTER（当前为"家宽"）。
#
set -uo pipefail

REPO="steven754/epic-freebies-helper"
WF="epic-gamer.yml"
URL="${1:-}"
FILTER="${2:-}"

if [[ -z "$URL" ]]; then
  echo "用法: $0 <SUBSCRIPTION_URL> [NODE_FILTER]" >&2
  exit 2
fi

TMP="$(mktemp /tmp/relay_sub.XXXXXX.txt)"
trap 'rm -f "$TMP"' EXIT

echo "==> [1/6] 拉取订阅: $URL"
HTTP_CODE=$(curl -sS -m 25 -w '%{http_code}' -o "$TMP" "$URL" 2>/dev/null)
RC=$?
if [[ $RC -ne 0 || "$HTTP_CODE" != "200" ]]; then
  echo "!! 订阅拉取失败 (curl rc=$RC, http=$HTTP_CODE)。不创建 gist，直接退出。" >&2
  exit 1
fi
echo "    订阅大小: $(wc -c < "$TMP") 字节"

echo "==> [2/6] 校验订阅内容（需含 ss:// 节点）"
NODE_COUNT=0
if grep -q 'ss://' "$TMP"; then
  NODE_COUNT=$(grep -o 'ss://' "$TMP" | wc -l | tr -d ' ')
elif grep -q 'proxies:' "$TMP"; then
  NODE_COUNT=$(grep -c 'server:' "$TMP")
else
  if base64 -d < "$TMP" 2>/dev/null | grep -q 'ss://'; then
    NODE_COUNT=$(base64 -d < "$TMP" 2>/dev/null | grep -o 'ss://' | wc -l | tr -d ' ')
  fi
fi
if [[ "$NODE_COUNT" -lt 1 ]]; then
  echo "!! 订阅内容校验失败：未检出任何 ss:// 节点。不创建 gist，直接退出。" >&2
  exit 1
fi
echo "    检出节点数: $NODE_COUNT"

echo "==> [3/6] 发到 secret(unlisted) gist"
GIST_URL=$(gh gist create "$TMP" 2>/dev/null)
if [[ -z "$GIST_URL" ]]; then
  echo "!! gh gist create 失败。退出（未改 PROXY_SUBSCRIPTION）。" >&2
  exit 1
fi
RAW_URL="${GIST_URL/gist.github.com/gist.githubusercontent.com}/raw"
GIST_ID=$(basename "$GIST_URL")
echo "    gist  : $GIST_URL"
echo "    raw   : $RAW_URL"

echo "==> [4/6] 设 PROXY_SUBSCRIPTION 秘钥"
gh secret set PROXY_SUBSCRIPTION --repo "$REPO" --body "$RAW_URL" 2>&1 | tail -2

if [[ -n "$FILTER" ]]; then
  echo "==> [4b] 覆盖 PROXY_NODE_FILTER=$FILTER"
  gh variable set PROXY_NODE_FILTER --repo "$REPO" --body "$FILTER" 2>&1 | tail -2
fi

echo "==> [5/6] 触发工作流"
sleep 3
gh workflow run "$WF" --repo "$REPO" 2>&1 | tail -3
RUN_ID=$(gh run list --repo "$REPO" --workflow "$WF" -L 1 --json databaseId --jq '.[0].databaseId')
echo "    run id : $RUN_ID"
echo "    run url: https://github.com/$REPO/actions/runs/$RUN_ID"

echo "==> [6/6] 等桥步骤跑完即删 gist（关掉凭证窗口）"
BRIDGE_DONE=0
for i in $(seq 1 75); do   # 75 * 20s = 25min
  sleep 20
  RUN_STATUS=$(gh run view "$RUN_ID" --repo "$REPO" --json status --jq '.status' 2>/dev/null)
  BRIDGE=$(gh run view "$RUN_ID" --repo "$REPO" --json steps --jq \
    '.steps[]? | select(.name=="Set up local proxy bridge") | .status + " " + (.conclusion // "")' 2>/dev/null | tail -1)
  if [[ "$RUN_STATUS" == "completed" ]]; then
    echo "    工作流已结束 (bridge=$BRIDGE)"
    BRIDGE_DONE=1
    break
  fi
  if [[ "$BRIDGE" == "completed"* || "$BRIDGE" == *" failure" || "$BRIDGE" == *" success" ]]; then
    echo "    桥步骤已执行 ($BRIDGE)，删除 gist"
    BRIDGE_DONE=1
    break
  fi
  echo "    ... 等待桥步骤 (${i}/75, run=$RUN_STATUS, bridge=$BRIDGE)"
done

if [[ "$BRIDGE_DONE" -eq 1 ]]; then
  gh gist delete --yes "$GIST_ID" 2>&1 | tail -1 && echo "    已删除 gist $GIST_ID"
else
  echo "!! 25 分钟内桥步骤未确认完成，保留 gist $GIST_ID 人工处理（raw=$RAW_URL）" >&2
fi
echo "DONE"
