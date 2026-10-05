#!/usr/bin/env bash
# 针对运行中的服务（默认 http://localhost:8000）演示完整业务流程。
set -euo pipefail

BASE="${BASE_URL:-http://localhost:8000}"
say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

say "健康检查"
curl -s "$BASE/health"; echo

say "判定示例：demo-derived-1 在 2026-03-01 可用于 research（交集仅 research）"
curl -s "$BASE/permissions/check?version_id=demo-derived-1&use=research&at=2026-03-01T00:00:00Z"; echo

say "判定示例：2026-07-01 申请 review（被 demo-root-a 阻断）"
curl -s "$BASE/permissions/check?version_id=demo-derived-1&use=review&at=2026-07-01T00:00:00Z"; echo

say "区间分段：demo-derived-1 的 review 在 2026-01-15 ~ 2026-07-15 的可用片段与阻断原因"
curl -s "$BASE/permissions/timeline?version_id=demo-derived-1&use=review&start=2026-01-15T00:00:00Z&end=2026-07-15T00:00:00Z"; echo

say "区间分段：同一区间申请 research（2 月 1 日起持续允许，6 月 1 日依据变更仍切分片段）"
curl -s "$BASE/permissions/timeline?version_id=demo-derived-1&use=research&start=2026-01-15T00:00:00Z&end=2026-07-15T00:00:00Z"; echo

say "区间分段错误：start 不早于 end -> 422 invalid_interval"
curl -s "$BASE/permissions/timeline?version_id=demo-derived-1&use=research&start=2026-07-15T00:00:00Z&end=2026-01-15T00:00:00Z"; echo

say "登记新派生版本（父版本 demo-root-a）"
curl -s -X POST "$BASE/versions" -H 'Content-Type: application/json' \
  -d '{"version_id":"example-v1","parent_ids":["demo-root-a"],"note":"调用示例"}'; echo

say "提交许可变更"
curl -s -X POST "$BASE/license-changes" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","version_id":"example-v1","effective_at":"2026-03-01T00:00:00Z","allowed_uses":["research"]}'; echo

say "重复提交：同标识同内容 -> 200 replayed=true"
curl -s -X POST "$BASE/license-changes" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","version_id":"example-v1","effective_at":"2026-03-01T00:00:00Z","allowed_uses":["research","research"]}'; echo

say "冲突 1：同标识不同内容 -> 409"
curl -s -X POST "$BASE/license-changes" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","version_id":"example-v1","effective_at":"2026-03-01T00:00:00Z","allowed_uses":["commercial"]}'; echo

say "冲突 2：同版本同生效时刻不同变更 -> 409"
curl -s -X POST "$BASE/license-changes" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c2","version_id":"example-v1","effective_at":"2026-03-01T00:00:00Z","allowed_uses":["research"]}'; echo

say "无有效许可（变更生效之前）-> allowed=false"
curl -s "$BASE/permissions/check?version_id=example-v1&use=research&at=2026-02-01T00:00:00Z"; echo

say "预演（不写入）：假设 demo-root-a 自 2026-04-01 起放开 commercial"
curl -s -X POST "$BASE/license-changes/preview" -H 'Content-Type: application/json' \
  -d '{"change_id":"preview-a-commercial","version_id":"demo-root-a","effective_at":"2026-04-01T00:00:00Z","allowed_uses":["research","review","commercial"],"use":"commercial","at":"2026-05-01T00:00:00Z"}'; echo

say "预演：查询时刻早于生效时刻 -> impacted_versions 为空（不误报）"
curl -s -X POST "$BASE/license-changes/preview" -H 'Content-Type: application/json' \
  -d '{"change_id":"preview-a-commercial","version_id":"demo-root-a","effective_at":"2026-04-01T00:00:00Z","allowed_uses":["research","review","commercial"],"use":"commercial","at":"2026-03-01T00:00:00Z"}'; echo

say "预演：相同标识与内容重放 -> replayed=true 且无影响（不写入）"
curl -s -X POST "$BASE/license-changes/preview" -H 'Content-Type: application/json' \
  -d '{"change_id":"demo-chg-a-1","version_id":"demo-root-a","effective_at":"2026-01-01T00:00:00Z","allowed_uses":["review","research"],"use":"research","at":"2026-05-01T00:00:00Z"}'; echo

say "作废：作废 example-c1（登记有误），返回回执"
curl -s -X POST "$BASE/license-changes/revocations" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","revocation_id":"rev-example-c1","reason":"允许用途登记有误，撤回"}'; echo

say "作废重试：同一作废标识与内容 -> 200 replayed=true，返回原回执"
curl -s -X POST "$BASE/license-changes/revocations" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","revocation_id":"rev-example-c1","reason":"允许用途登记有误，撤回"}'; echo

say "作废冲突 1：同一作废标识换原因 -> 409"
curl -s -X POST "$BASE/license-changes/revocations" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","revocation_id":"rev-example-c1","reason":"换个原因"}'; echo

say "作废冲突 2：另一作废标识重复作废同一变更 -> 409"
curl -s -X POST "$BASE/license-changes/revocations" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","revocation_id":"rev-example-c1-again","reason":"允许用途登记有误，撤回"}'; echo

say "作废目标不存在 -> 404"
curl -s -X POST "$BASE/license-changes/revocations" -H 'Content-Type: application/json' \
  -d '{"change_id":"no-such-change","revocation_id":"rev-ghost","reason":"x"}'; echo

say "作废追溯：按作废标识取回回执"
curl -s "$BASE/license-changes/revocations/rev-example-c1"; echo

say "原变更仍可按原接口查询，附带 revocation 回执"
curl -s "$BASE/license-changes/example-c1"; echo

say "作废立即对所有查询时刻生效：example-v1 再无未作废变更 -> no_valid_license"
curl -s "$BASE/permissions/check?version_id=example-v1&use=research&at=2026-05-01T00:00:00Z"; echo

say "重放已作废变更不能恢复：仍 replayed=true 且带 revocation"
curl -s -X POST "$BASE/license-changes" -H 'Content-Type: application/json' \
  -d '{"change_id":"example-c1","version_id":"example-v1","effective_at":"2026-03-01T00:00:00Z","allowed_uses":["research"]}'; echo

say "判定凭证：首次签发 demo-derived-1 的 review @ 2026-03-01（被 root-b 拒绝，拒绝也留痕），201"
curl -s -X POST "$BASE/permissions/vouchers" -H 'Content-Type: application/json' \
  -d '{"voucher_id":"example-voucher-1","version_id":"demo-derived-1","use":" review ","at":"2026-03-01T08:00:00+08:00"}'; echo

say "凭证重试：去空格用途 + 同一 UTC 瞬间（+08:00 与 Z 等价）-> 200 replayed=true，原凭证逐字段一致"
curl -s -X POST "$BASE/permissions/vouchers" -H 'Content-Type: application/json' \
  -d '{"voucher_id":"example-voucher-1","version_id":"demo-derived-1","use":"review","at":"2026-03-01T00:00:00Z"}'; echo

say "凭证追溯：按标识取回首次保存的判定"
curl -s "$BASE/permissions/vouchers/example-voucher-1"; echo

say "凭证冲突：同一标识换用途 -> 409（原凭证不变）"
curl -s -X POST "$BASE/permissions/vouchers" -H 'Content-Type: application/json' \
  -d '{"voucher_id":"example-voucher-1","version_id":"demo-derived-1","use":"research","at":"2026-03-01T00:00:00Z"}'; echo

say "凭证错误 1：未知版本 -> 404，不留凭证"
curl -s -X POST "$BASE/permissions/vouchers" -H 'Content-Type: application/json' \
  -d '{"voucher_id":"example-voucher-x","version_id":"no-such-version","use":"research","at":"2026-03-01T00:00:00Z"}'; echo

say "凭证错误 2：无时区时刻 -> 422，不留凭证"
curl -s -X POST "$BASE/permissions/vouchers" -H 'Content-Type: application/json' \
  -d '{"voucher_id":"example-voucher-x","version_id":"demo-derived-1","use":"research","at":"2026-03-01T00:00:00"}'; echo

say "凭证错误 3：空用途 -> 422，不留凭证"
curl -s -X POST "$BASE/permissions/vouchers" -H 'Content-Type: application/json' \
  -d '{"voucher_id":"example-voucher-x","version_id":"demo-derived-1","use":"   ","at":"2026-03-01T00:00:00Z"}'; echo

say "凭证错误 4：未知凭证标识 -> 404"
curl -s "$BASE/permissions/vouchers/no-such-voucher"; echo

say "凭证不可变：允许的凭证签发后再收紧/作废，GET 仍返回首次结果"
curl -s -X POST "$BASE/permissions/vouchers" -H 'Content-Type: application/json' \
  -d '{"voucher_id":"example-voucher-2","version_id":"demo-derived-1","use":"research","at":"2026-05-01T00:00:00Z"}'; echo
curl -s -X POST "$BASE/license-changes/revocations" -H 'Content-Type: application/json' \
  -d '{"change_id":"demo-chg-d1-1","revocation_id":"rev-demo-d1-1","reason":"示例：收紧后凭证仍应保留首次结果"}' >/dev/null || true
echo "# 实时判定此刻可能已变化："
curl -s "$BASE/permissions/check?version_id=demo-derived-1&use=research&at=2026-05-01T00:00:00Z"; echo
echo "# 而凭证恒为首次保存的 allowed=true："
curl -s "$BASE/permissions/vouchers/example-voucher-2"; echo
