#!/usr/bin/env python3
"""在 GitHub Actions runner 上把 Clash 订阅变成浏览器可用的本地代理。

为什么需要这一层
----------------
订阅里的 vmess / vless / trojan / hysteria2 等私有协议浏览器不能直连，必须先由
mihomo(clash.meta) 转成 http+socks5 混合端口，再通过 BROWSER_PROXY 喂给 Camoufox。

为什么不能"连上就算成功"
------------------------
机场的默认策略几乎总是"延迟最低优先"，而在 GitHub Actions 上延迟最低的节点
通常就是离 Azure 机房最近的中转，出口落在 AS8075(Microsoft)/AS16509(Amazon)
这类云厂商网段。这类 IP 被 hCaptcha 与 Epic 的风控重点照顾——社区反馈的
`captcha_invalid` 就是这么来的。所以：
  * 代理出口 IP 与直连 IP 相同 => 桥等于没生效，绝不能写 BROWSER_PROXY，
    否则只是白白改变浏览器的网络指纹，让验证码更难；
  * 出口是机房网段 => 记为警告，并把节点名和 ASN 打进 summary，便于换节点。
    机房 IP 不仅会让 hCaptcha 返回 `captcha_invalid`，更会在登录"成功"后让
    store.epicgames.com 仍报告 `isloggedin=false`——两种都是 Epic 对云厂商
    网段的风控，本质是同一个问题：没有住宅/家宽出口就过不了领取。

本脚本做的事
------------
1. 下载并启动 mihomo，用 proxy-providers 拉取订阅；
2. 逐个节点切换出口，实测真实 egress IP + ASN 组织，输出一张表；
3. 按 住宅 > 未知 > 机房 的优先级自动挑一个节点并选中（组类型用 select，
   手动选择不会被 url-test 的测速周期覆盖）；
4. 出口 IP 与直连不同才写 BROWSER_PROXY 到 $GITHUB_ENV。

本地自测：`python3 proxy_bridge.py --self-test`（只跑分类器与配置生成，不联网）。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

WORK = os.environ.get("MIHOMO_WORKDIR", "/tmp/mihomo")
# 端口可用环境变量覆盖，方便在已有 Clash/mihomo 客户端占用 7890 的机器上做本地测试。
# Actions 的 runner 是干净虚拟机，用默认值即可。
MIXED_PORT = int(os.environ.get("MIHOMO_MIXED_PORT", "7890"))
API_PORT = int(os.environ.get("MIHOMO_API_PORT", "9090"))
API = f"http://127.0.0.1:{API_PORT}"
MIXED_PROXY = f"http://127.0.0.1:{MIXED_PORT}"
GROUP = "PROXY"
PROVIDER = "sub"

# mihomo 的内置代理。注意 COMPATIBLE：它是 *空分组* 的兜底项，会出现在
# /proxies/<group> 的 all 数组里（同时 emptyFallback="COMPATIBLE"）。
# 所以 "all 非空" 完全不能说明订阅加载成功——必须按名字把它们排除掉，
# 否则订阅拉取失败时也会被当成"有节点"，继而把一个假代理塞给浏览器。
BUILTIN_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"}

MAX_PROBE = 40  # 最多实测多少个节点的出口
PROBE_TIMEOUT = 8  # 单个节点实测超时（秒）
PROBE_BUDGET = 240  # 实测阶段总预算（秒），超了就用手上的结果
FALLBACK_PROBE = 8  # 并发测速判定"全死"时，仍复核前几个节点
GOOD_ENOUGH = 3  # 已找到多少个非机房节点就提前停止实测

# ---------------------------------------------------------------------------
# 出口归属判定
# ---------------------------------------------------------------------------
# 命中住宅特征 => 直接把该 IP 当作住宅/家宽出口。运营商名比 ASN 号可靠，
# 所以这里主要看 org 里的关键词。中国三大运营商 + 常见海外家宽品牌。
RESIDENTIAL_HINTS = (
    "chinanet",
    "china mobile",
    "chinamobile",
    "china unicom",
    "chinaunicom",
    "chinatelecom",
    "cmnet",
    "uninet",
    "telecom",
    "unicom",
    "broadband",
    "breitband",
    "comcast",
    "verizon",
    "at&t",
    "spectrum",
    "centurylink",
    "cox communications",
    "vodafone",
    "deutsche telekom",
    "orange s.a",
    "kddi",
    "softbank",
    "residential",
    "家宽",
    "住宅",
    "fiber",
    "cable",
)

# 命中机房特征 => 对风控没有帮助，只作为最后兜底。
DATACENTER_HINTS = (
    "microsoft",
    "amazon",
    "google",
    "cloudflare",
    "fastly",
    "digitalocean",
    "vultr",
    "choopa",
    "linode",
    "akamai",
    "hetzner",
    "ovh",
    "oracle",
    "alibaba",
    "aliyun",
    "tencent",
    "huawei",
    "ucloud",
    "gcore",
    "zenlayer",
    "contabo",
    "leaseweb",
    "colocrossing",
    "m247",
    "datacamp",
    "quadranet",
    "psychz",
    "sharktech",
    "racknerd",
    "hostwinds",
    "ionos",
    "scaleway",
    "upcloud",
    "equinix",
    "cdn77",
    "stackpath",
    "datacenter",
    "data center",
    "hosting",
    "cloud",
    "server",
    "idc",
    "buyvm",
    "frantech",
    "incapsula",
    "imperva",
    "limelight",
    "phoenixnap",
    "hivelocity",
    "aeza",
    "hostkey",
)

TIER_RESIDENTIAL = 3
TIER_UNKNOWN = 2
TIER_DATACENTER = 1

TIER_LABEL = {
    TIER_RESIDENTIAL: "住宅",
    TIER_UNKNOWN: "未知",
    TIER_DATACENTER: "机房",
}


def _norm_org(s: str) -> str:
    """只去掉分隔符（连字符/点/下划线/空格/&），保留字母与中文，
    让 `G-Core` 能命中 `gcore`、`Microsoft-Corporation` 能命中 `microsoft`，
    同时中文住宅特征（家宽/住宅）不被清空。

    注意：绝不能用 `[^a-z0-9]` 清空所有非 ASCII——那样会把 `家宽`/`住宅`
    变成空串，而空串是任何字符串的子串，会导致全部误判成住宅。
    """
    return re.sub(r"[\s\-_./&]", "", (s or "").lower())


def classify_org(org: str) -> int:
    """按 ASN 组织名判定出口类型。住宅特征优先于机房特征。

    注意：ASN 组织名里常带连字符（如 `G-Core Labs`、`Microsoft-Corporation`），
    直接做子串匹配会漏掉。先归一化分隔符再比，避免把明明的机房网段误判成"未知"。
    """
    text = _norm_org(org)
    if not text:
        return TIER_UNKNOWN
    for hint in RESIDENTIAL_HINTS:
        nh = _norm_org(hint)
        if nh and nh in text:
            return TIER_RESIDENTIAL
    for hint in DATACENTER_HINTS:
        nh = _norm_org(hint)
        if nh and nh in text:
            return TIER_DATACENTER
    return TIER_UNKNOWN


# ---------------------------------------------------------------------------
# HTTP 工具
# ---------------------------------------------------------------------------
def fetch_json(url: str, timeout: int = 10, proxy: str | None = None) -> dict:
    """GET 一个 JSON 接口。显式传代理，避免被环境变量里的代理悄悄改写。"""
    handlers = [
        urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
    ]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def egress(proxy: str | None = None, timeout: int = 10) -> tuple[str, str, str]:
    """返回 (出口 IP, ASN 组织, 国家)。两个数据源互为备份。"""
    for url in ("https://ipinfo.io/json", "https://ifconfig.co/json"):
        try:
            data = fetch_json(url, timeout=timeout, proxy=proxy)
        except Exception:
            continue
        ip = str(data.get("ip") or "").strip()
        if not ip:
            continue
        asn = str(data.get("asn") or "").strip()
        asn_org = str(data.get("asn_org") or "").strip()
        org = str(data.get("org") or "").strip()
        if not org:
            org = f"{asn} {asn_org}".strip() if asn_org else asn
        elif asn and not org.upper().startswith("AS"):
            org = f"{asn} {org}"
        country = str(data.get("country") or data.get("country_iso") or "").strip()
        return ip, org, country
    return "", "", ""


def api_get(path: str, timeout: int = 5):
    return fetch_json(f"{API}{path}", timeout=timeout)


def api_put(path: str, payload: dict, timeout: int = 5) -> bool:
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# mihomo
# ---------------------------------------------------------------------------
CONFIG_TEMPLATE = """mixed-port: {port}
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:{api_port}
proxy-providers:
  sub:
    type: http
    url: {url}
    interval: 86400
    path: ./providers/sub.yaml
    filter: {node_filter}
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
proxy-groups:
  - name: {group}
    type: select
    use: [sub]
rules:
  - MATCH,{group}
"""


def build_config(subscription: str, node_filter: str) -> str:
    """生成 mihomo 配置。URL 与正则用 json.dumps 转义——JSON 字符串本身就是
    合法的 YAML 双引号标量，比手写引号安全得多（订阅链接里常带 & 和 #）。
    ensure_ascii=False 让中文正则原样可读，否则会被转成 \\uXXXX 看不出写了什么。"""

    def dump(text: str) -> str:
        return json.dumps(text, ensure_ascii=False)

    return CONFIG_TEMPLATE.format(
        port=MIXED_PORT,
        api_port=API_PORT,
        url=dump(subscription),
        node_filter=dump(node_filter or ".*"),
        group=GROUP,
    )


def log_line(text: str) -> None:
    print(text, flush=True)


def warn(text: str) -> None:
    # ::warning:: 会同时落到日志和运行页的注解里
    print(f"::warning::{text}", flush=True)


def write_env(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_ENV")
    if not path:
        log_line(f"(本地模式) {key}={value}")
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{key}={value}\n")


def write_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(markdown)


def download_mihomo(work: str) -> bool:
    """准备 mihomo 二进制。

    二进制走 curl：发布日期资产会 302 跳到 objects.githubusercontent.com，
    curl 处理跳转、重试、大文件都比 urllib 稳（这也是原先工作流里验证过的路径）。
    API 查询仍走 urllib 的显式直连 opener，避免被环境变量里的代理悄悄改写。

    MIHOMO_BIN 指向一个已存在的二进制时会直接使用它（本地测试 / 自行缓存时用）。
    """
    binary = os.path.join(work, "mihomo")
    prebuilt = (os.environ.get("MIHOMO_BIN") or "").strip()
    if prebuilt and os.path.exists(prebuilt):
        shutil.copy2(prebuilt, binary)
        os.chmod(binary, 0o755)
        log_line(f"使用预置 mihomo 二进制: {prebuilt}")
        return True

    try:
        release = fetch_json(
            "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", timeout=20
        )
        version = str(release.get("tag_name") or "").strip()
    except Exception:
        version = ""
    if not version:
        warn("无法获取 mihomo 版本，本次运行将不使用代理（机房 IP 直连）")
        return False
    log_line(f"mihomo version: {version}")

    # compatible 构建面向 GOAMD64=v1，任何 x86_64 runner 都能跑；个别版本缺这个产物时退回普通构建。
    # MIHOMO_ASSET 可以覆盖资产名（本地 e2e 测试用 darwin 构建时会用到），{version} 为占位符。
    override = (os.environ.get("MIHOMO_ASSET") or "").strip()
    if override:
        candidates = [override.format(version=version)]
    else:
        candidates = [
            f"mihomo-linux-amd64-compatible-{version}.gz",
            f"mihomo-linux-amd64-{version}.gz",
        ]

    gz = os.path.join(work, "mihomo.gz")
    for name in candidates:
        url = f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/{name}"
        log_line(f"下载 {name} ...")
        done = subprocess.run(
            ["curl", "-sfL", "--retry", "2", "--retry-delay", "3",
             "--connect-timeout", "20", "--max-time", "120", url, "-o", gz],
            check=False,
        ).returncode == 0
        if not done:
            done = _download_via_urllib(url, gz)
        if done and os.path.exists(gz) and os.path.getsize(gz) > 0:
            break
    else:
        warn("无法下载 mihomo，本次运行将不使用代理（机房 IP 直连）")
        return False

    subprocess.run(["gunzip", "-f", gz], check=True)
    os.chmod(binary, 0o755)
    return True


def _download_via_urllib(url: str, dest: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=180) as resp, open(dest, "wb") as fh:
            shutil.copyfileobj(resp, fh)
        return True
    except Exception:
        return False


def start_mihomo(work: str) -> bool:
    config = os.path.join(work, "config.yaml")
    log = os.path.join(work, "mihomo.log")
    with open(log, "wb") as fh:
        subprocess.Popen(
            [os.path.join(work, "mihomo"), "-d", work, "-f", config],
            stdout=fh,
            stderr=fh,
            start_new_session=True,
        )
    for _ in range(30):
        try:
            api_get("/version", timeout=3)
            break
        except Exception:
            time.sleep(2)
    else:
        warn("mihomo 控制端口未就绪")
        return False

    # 混合端口起不来时 mihomo 照样活着，只是后续所有"经代理"的请求其实都发到了
    # 别的进程（或压根没发出去）——这类假阳性必须挡住，否则会把 BROWSER_PROXY
    # 指向一个不属于我们的端口。
    if "Mixed(http+socks) server error" in read_log(log):
        warn(f"mihomo 混合端口 {MIXED_PORT} 无法监听（可能被占用），本次运行不使用代理")
        subprocess.run(["tail", "-20", log])
        return False
    return True


def read_log(log: str) -> str:
    if not os.path.exists(log):
        return ""
    with open(log, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def wait_for_nodes() -> tuple[list[str], str]:
    """等订阅真正加载出节点，返回 (节点名列表, 失败原因)。

    判据是 proxy-provider 自己有没有拉到东西（/providers/proxies/<name>），
    而不是代理组 all 的长度——见 BUILTIN_NAMES 上面的说明。provider 拉取失败时
    mihomo 不会报错退出，只是让分组空着，所以这里必须主动区分这两种情况。
    """
    provider_seen = False
    for _ in range(40):
        names: list[str] = []
        try:
            data = api_get(f"/providers/proxies/{PROVIDER}", timeout=3)
            provider_seen = True
            names = [
                str(p.get("name"))
                for p in (data.get("proxies") or [])
                if str(p.get("name")) not in BUILTIN_NAMES
            ]
        except Exception:
            names = []
        if names:
            return names, ""
        # 首次拉取就明确报错时不用再干等：proxy-provider 的 interval 是 86400，
        # 首次失败后当天不会重试，继续等只是白白拖长运行时间。
        if not provider_seen and provider_pull_errors():
            break
        time.sleep(3)

    # provider 拉不出来时退回读分组，至少能看出里面是什么
    group_names: list[str] = []
    try:
        data = api_get(f"/proxies/{GROUP}", timeout=3)
        group_names = [
            str(n) for n in (data.get("all") or []) if str(n) not in BUILTIN_NAMES
        ]
    except Exception:
        pass

    if group_names:
        return group_names, ""

    if provider_seen:
        return [], f"provider {PROVIDER} 已注册但没拉到任何节点（订阅链接失效、被墙或内容不是 Clash 格式）"
    return [], f"provider {PROVIDER} 始终没有出现（订阅拉取失败）"


def provider_pull_errors() -> list[str]:
    """从 mihomo 日志里捞出 provider 拉取相关报错，直接写进 summary 便于定位。"""
    log = os.path.join(WORK, "mihomo.log")
    if not os.path.exists(log):
        return []
    hits: list[str] = []
    try:
        with open(log, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "provider" in line.lower() and ("error" in line.lower() or "failed" in line.lower()):
                    hits.append(line.strip())
    except OSError:
        return []
    return hits[-5:]


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def rank_by_delay(names: list[str], timeout_ms: int = 5000) -> list[str]:
    """用 mihomo 的分组测速接口把节点按"先活后死"排序。

    `/group/<name>/delay` 会**并发**测速，比逐个切换出口快一个数量级；死节点省掉
    每个 8 秒的 egress 探测超时。测速 URL 用 ipinfo 而不是 gstatic，避免 gstatic
    本身被墙造成的误判。

    注意这个方法只返回**可用**节点，全部不可用时直接返回 HTTP 504
    （`{"message":"get delay: all proxies timeout"}`），所以 504 是"全死"的明确信号，
    不是接口故障——必须和调用异常区分开。
    """
    try:
        data = api_get(
            f"/group/{GROUP}/delay?url=https://ipinfo.io/ip&timeout={timeout_ms}",
            timeout=timeout_ms // 1000 + 15,
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 504:
            log_line("分组测速（并发）：全部节点超时")
            return []
        return names
    except Exception:
        return names

    # 兼容两种返回：{node: delay} 或 {delay: {node: delay}}
    if isinstance(data.get("delay"), dict):
        data = data["delay"]
    delays = {str(k): v for k, v in data.items() if isinstance(v, (int, float))}
    if not delays:
        log_line("分组测速（并发）：未返回任何可用节点")
        return []

    alive = sorted((n for n in names if delays.get(n, 0) > 0), key=lambda n: delays[n])
    dead = [n for n in names if delays.get(n, 0) <= 0]
    log_line(f"分组测速（并发）：可用 {len(alive)} / {len(names)}")
    return alive + dead


def probe_nodes(names: list[str]) -> list[dict]:
    """逐个节点切换出口并实测真实 IP/ASN。切换是全局状态，只能串行。"""
    results: list[dict] = []
    started = time.time()
    good = 0
    for idx, name in enumerate(names[:MAX_PROBE], 1):
        if time.time() - started > PROBE_BUDGET:
            log_line(f"实测预算用尽，已测 {idx - 1}/{min(len(names), MAX_PROBE)} 个节点")
            break
        t0 = time.time()
        if not api_put(f"/proxies/{GROUP}", {"name": name}, timeout=5):
            log_line(f"[{idx:>2}] {name} -> 切换失败")
            continue
        ip, org, country = egress(proxy=MIXED_PROXY, timeout=PROBE_TIMEOUT)
        elapsed = int((time.time() - t0) * 1000)
        tier = classify_org(org) if ip else TIER_DATACENTER
        tag = TIER_LABEL[tier] if ip else "不可用"
        log_line(f"[{idx:>2}] {tag} {elapsed:>5}ms  {ip or '-':<16} {org or '-':<40} {name}")
        if not ip:
            continue
        results.append(
            {"name": name, "ip": ip, "org": org, "country": country,
             "tier": tier, "ms": elapsed}
        )
        if tier == TIER_RESIDENTIAL:
            good += 1
            if good >= GOOD_ENOUGH:
                log_line(f"已找到 {good} 个住宅出口，提前结束实测")
                break
    return results


def pick(results: list[dict]) -> dict | None:
    """先看等级（住宅 > 未知 > 机房），同级取延迟最低。"""
    if not results:
        return None
    return sorted(results, key=lambda r: (-r["tier"], r["ms"]))[0]


def main() -> int:
    subscription = (os.environ.get("SUBSCRIPTION") or "").strip()
    node_filter = (os.environ.get("NODE_FILTER") or "").strip()
    if not subscription:
        warn("PROXY_SUBSCRIPTION 为空，跳过代理桥")
        return 0

    if os.path.isdir(WORK):
        shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(os.path.join(WORK, "providers"), exist_ok=True)

    if not download_mihomo(WORK):
        return 0

    with open(os.path.join(WORK, "config.yaml"), "w", encoding="utf-8") as fh:
        fh.write(build_config(subscription, node_filter))

    if not start_mihomo(WORK):
        return 0

    names, reason = wait_for_nodes()
    log_line(f"订阅节点数: {len(names)} | 过滤正则: {node_filter or '.*'}")
    if not names:
        warn(f"订阅未加载出任何节点：{reason}")
        log_line(f"订阅节点数: 0 | 原因: {reason}")
        errors = provider_pull_errors()
        if errors:
            log_line("--- provider 报错 ---")
            for line in errors:
                log_line(line)
        write_summary(
            "\n## 代理出口实测\n\n"
            "订阅未加载出任何节点，本次运行不使用代理（走机房直连）。\n\n"
            f"- 原因: {reason}\n"
            + ("".join(f"- `{e}`\n" for e in errors))
        )
        log_line("--- mihomo.log (tail 60) ---")
        subprocess.run(["tail", "-60", os.path.join(WORK, "mihomo.log")])
        return 0

    log_line(f"--- 节点名（前 {min(len(names), 60)} 个）---")
    for name in names[:60]:
        log_line(name)
    log_line("--- 节点名结束 ---")

    direct_ip, direct_org, _ = egress(timeout=10)
    log_line(f"直连出口: {direct_ip or '未知'}  {direct_org}")

    # 先用并发测速把节点分成"活/死"。全死（504）时仍按顺序抽几个实测一遍——
    # 万一测速本身失灵，不至于把一个其实能用的订阅判死。
    ranked = rank_by_delay(names)
    if ranked:
        candidates = ranked
    else:
        candidates = names[:FALLBACK_PROBE]
        log_line(f"并发测速判定全部不可用，抽前 {len(candidates)} 个节点逐个复核")

    log_line("--- 逐节点实测出口 ---")
    results = probe_nodes(candidates)
    log_line("--- 实测结束 ---")

    best = pick(results)
    if best is None:
        warn("所有节点实测均失败，本次运行不使用代理")
        log_line("--- mihomo.log (tail 60) ---")
        subprocess.run(["tail", "-60", os.path.join(WORK, "mihomo.log")])
        return 0

    api_put(f"/proxies/{GROUP}", {"name": best["name"]})
    write_env("PROXY_PICKED_NODE", best["name"])

    # 选中节点后要重新建立出站连接，首次请求可能偏慢；只试一次会把"可用但慢"
    # 误判成"未生效"，从而白白放弃一个能用的代理。给它几次机会。
    proxied_ip, proxied_org = "", ""
    for attempt in range(3):
        proxied_ip, proxied_org, _ = egress(proxy=MIXED_PROXY, timeout=12)
        if proxied_ip and proxied_ip != direct_ip:
            break
        if attempt < 2:
            time.sleep(3)
    effective = bool(proxied_ip) and proxied_ip != direct_ip
    tier_label = TIER_LABEL[best["tier"]]

    # summary：把整张表和结论都留下，换节点时有据可查
    table = "\n".join(
        f"| {TIER_LABEL[r['tier']]} | `{r['name']}` | {r['ip']} | {r['org']} | {r['ms']}ms |"
        for r in sorted(results, key=lambda r: (-r["tier"], r["ms"]))[:30]
    )
    write_summary(
        "\n## 代理出口实测\n\n"
        f"- 直连出口: `{direct_ip or '未知'}` {direct_org}\n"
        f"- 选中节点: `{best['name']}`（{tier_label}，{best['ms']}ms）\n"
        f"- 代理出口: `{proxied_ip or '无响应'}` {proxied_org}\n"
        f"- 桥是否生效: {'是' if effective else '否'}\n\n"
        "| 类型 | 节点 | 出口 IP | ASN 组织 | 耗时 |\n"
        "| --- | --- | --- | --- | --- |\n"
        f"{table}\n"
    )

    if not effective:
        # 出口没变说明节点没真正生效。这种情况绝不写 BROWSER_PROXY：带着一个
        # 等于直连的代理只会改变浏览器网络指纹，让 hCaptcha 更难，却拿不到换 IP 的好处。
        warn(f"代理出口与直连相同（{proxied_ip or '无响应'}），本次运行不使用代理")
        log_line("--- mihomo.log (tail 60) ---")
        subprocess.run(["tail", "-60", os.path.join(WORK, "mihomo.log")])
        return 0

    write_env("BROWSER_PROXY", MIXED_PROXY)
    log_line(
        f"本地代理桥就绪 | 直连={direct_ip} | 代理={proxied_ip} | "
        f"节点={best['name']} | 类型={tier_label}"
    )

    # 出口已经真正改变（否则前面就 return 了），所以仍然把代理喂给浏览器——
    # 这是当前订阅里能拿到的最好出口。但机房/未知网段对 Epic 风控几乎没帮助，
    # 必须明确告诉用户：本次运行很可能过不了登录/领取。
    alive_tiers = [r["tier"] for r in results]
    has_residential = any(t >= TIER_RESIDENTIAL for t in alive_tiers)
    if not has_residential:
        # 全部可用出口都是机房/未知网段：Epic 会直接按风控处理。
        # 轻则登录页验证码过不去（captcha_invalid），重则登录"成功"但商店
        # 仍判定未登录（isloggedin=false），领取不会真正完成。
        warn(
            "订阅里全部可用出口都是机房/数据中心网段"
            f"（如 {proxied_org}），没有任何住宅/家宽(ISP)节点。"
            "Epic 会对这类云厂商 IP 做风控：要么 hCaptcha 过不去(captcha_invalid)，"
            "要么登录成功但 store.epicgames.com 仍报告 isloggedin=false，领取不会成功。"
            "要让工作流跑通，请改用含住宅/ISP 出口的订阅；若已有，"
            "用仓库变量 PROXY_NODE_FILTER 指定住宅节点名（如含 住宅/家宽/ISP/宽带 字样的节点）。"
        )
    elif best["tier"] < TIER_RESIDENTIAL:
        warn(
            "选中的仍是机房/未知节点（" + proxied_org + "），住宅节点不可用。"
            "Epic 可能仍以风控理由拒绝，建议优先使用住宅出口。"
        )
    return 0


def self_test() -> int:
    """离线自检：分类器与配置生成。"""
    cases = [
        ("AS8075 Microsoft Corporation", TIER_DATACENTER),
        ("AS16509 Amazon.com, Inc.", TIER_DATACENTER),
        ("AS4134 CHINANET-BACKBONE", TIER_RESIDENTIAL),
        ("AS9808 China Mobile Communications Corporation", TIER_RESIDENTIAL),
        ("AS17621 China Unicom Shanghai", TIER_RESIDENTIAL),
        ("AS7922 Comcast Cable Communications, LLC", TIER_RESIDENTIAL),
        ("AS13335 Cloudflare, Inc.", TIER_DATACENTER),
        ("AS199524 G-Core Labs S.A.", TIER_DATACENTER),
        ("AS14061 DigitalOcean, LLC", TIER_DATACENTER),
        ("AS401120 Some Small Network", TIER_UNKNOWN),
        ("", TIER_UNKNOWN),
    ]
    failed = 0
    for org, expected in cases:
        got = classify_org(org)
        flag = "ok " if got == expected else "FAIL"
        if got != expected:
            failed += 1
        log_line(f"{flag} {org or '(空)':<48} -> {TIER_LABEL[got]}")

    cfg = build_config("https://example.com/sub?a=1&b=#frag", "住宅|Residential")
    assert 'url: "https://example.com/sub?a=1&b=#frag"' in cfg, cfg
    assert 'filter: "住宅|Residential"' in cfg, cfg
    assert "type: select" in cfg, cfg
    log_line("ok  配置生成：订阅链接与过滤正则均被正确转义")

    picked = pick(
        [
            {"name": "dc", "tier": TIER_DATACENTER, "ms": 10},
            {"name": "home", "tier": TIER_RESIDENTIAL, "ms": 900},
            {"name": "mystery", "tier": TIER_UNKNOWN, "ms": 50},
        ]
    )
    assert picked and picked["name"] == "home", picked
    log_line("ok  选点：住宅节点优先级高于低延迟机房节点")

    log_line(f"自检结果：{'全部通过' if failed == 0 else f'{failed} 项失败'}")
    return 1 if failed else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
