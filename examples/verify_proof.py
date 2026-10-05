#!/usr/bin/env python3
"""离线验签示例：核对凭证证明包的 Ed25519 签名，无需连接服务。

用法：
    python3 examples/verify_proof.py PROOF_JSON KEY_OR_KEYINFO

PROOF_JSON      POST /permissions/vouchers/{voucher_id}/proof 返回的 JSON
                （整个响应或仅其中的 proof 对象均可）。
KEY_OR_KEYINFO  公钥 PEM 文件，或 GET /signing-keys/{key_id} 返回的 JSON。

验签编码规则（canonical-json-v1，与证明包 signature.encoding 一致）：
    对 snapshot 对象整体做 JSON 序列化：UTF-8 编码；对象键按 Unicode 码点
    升序；无冗余空白（冒号、逗号后均无空格）；非 ASCII 字符原样输出；数组
    保持 snapshot 中的顺序；时间戳为 snapshot 中的定长 UTC 字符串
    YYYY-MM-DDTHH:MM:SS.ffffffZ。序列化结果的 UTF-8 字节串即被签名的消息，
    签名为 base64（RFC 4648）编码的 Ed25519 签名。

退出码：0 验签通过；1 验签失败或输入非法。
"""

from __future__ import annotations

import base64
import json
import sys

EXPECTED_ALGORITHM = "Ed25519"
EXPECTED_PAYLOAD_FORMAT = "canonical-json-v1"


def canonical_json(payload: object) -> str:
    """canonical-json-v1：键按码点排序、无冗余空白、UTF-8、非 ASCII 不转义。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _load_proof(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    # 兼容完整响应（{"replayed": ..., "proof": {...}}）与仅 proof 对象。
    return data.get("proof", data)


def _load_public_key(path: str) -> tuple[str, str | None]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except ValueError:
        return text, None  # 纯 PEM 文件
    return data["public_key_pem"], data.get("key_id")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 1
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        print("需要 cryptography 库：pip install cryptography", file=sys.stderr)
        return 1

    try:
        proof = _load_proof(argv[1])
        pem, pem_key_id = _load_public_key(argv[2])
    except (OSError, ValueError, KeyError) as exc:
        print(f"输入无法解析：{exc}", file=sys.stderr)
        return 1

    signature = proof.get("signature", {})
    if signature.get("algorithm") != EXPECTED_ALGORITHM:
        print(f"不支持的签名算法：{signature.get('algorithm')}", file=sys.stderr)
        return 1
    if signature.get("encoding", {}).get("payload_format") != EXPECTED_PAYLOAD_FORMAT:
        print(
            f"不支持的载荷编码：{signature.get('encoding', {}).get('payload_format')}",
            file=sys.stderr,
        )
        return 1
    if pem_key_id is not None and pem_key_id != signature.get("key_id"):
        print(
            f"密钥标识不匹配：证明包 {signature.get('key_id')} vs 公钥 {pem_key_id}",
            file=sys.stderr,
        )
        return 1

    payload = canonical_json(proof["snapshot"]).encode("utf-8")
    try:
        public_key = load_pem_public_key(pem.encode("utf-8"))
        public_key.verify(base64.b64decode(signature["value"]), payload)
    except InvalidSignature:
        print(
            f"验签失败：签名与快照不匹配（voucher_id={proof.get('voucher_id')}）",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # 公钥损坏、签名串非法等
        print(f"验签出错：{exc}", file=sys.stderr)
        return 1

    print(
        f"验签通过：voucher_id={proof['voucher_id']} "
        f"key_id={signature['key_id']} algorithm={EXPECTED_ALGORITHM}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
