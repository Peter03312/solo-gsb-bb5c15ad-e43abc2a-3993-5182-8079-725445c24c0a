"""Voucher proof packages: canonical signing payload and local Ed25519 keys.

研究审批把已签发的用途判定凭证交给离线审计方核验时，服务按凭证标识导出
证明包：首次判定的完整快照 + 签名算法 + 密钥标识 + 签名。签名覆盖快照整体
的规范化 JSON（canonical-json-v1），快照中的版本、用途、判定时刻、登记时刻、
祖先、依据、阻断原因与用途交集任一字段被篡改都无法通过验签。

密钥是本地持久文件（``SIGNING_KEY_DIR``）：每个密钥一对文件
``<key_id>.key``（PKCS8 PEM 私钥）与 ``<key_id>.pub.json``（公钥与元数据），
``active`` 文件记录当前活跃密钥标识。轮换只生成新密钥并切换指针：旧密钥文件
保留、旧公钥仍可获取、已固化的旧证明包永不重签。
"""

from __future__ import annotations

import base64
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROOF_ALGORITHM = "Ed25519"
PROOF_PAYLOAD_FORMAT = "canonical-json-v1"

# 验签编码规则：随证明包与公钥接口一起返回，离线审计方据此逐字节重建被签名消息。
PROOF_ENCODING_RULES: dict[str, str] = {
    "payload_format": PROOF_PAYLOAD_FORMAT,
    "payload_encoding": (
        "对 snapshot 对象整体做 JSON 序列化：UTF-8 编码；对象键按 Unicode 码点升序；"
        "无冗余空白（冒号、逗号后均无空格）；非 ASCII 字符原样输出（不做 \\uXXXX 转义）；"
        "数组保持 snapshot 中的顺序；时间戳为 snapshot 中的定长 UTC 字符串 "
        "YYYY-MM-DDTHH:MM:SS.ffffffZ。序列化结果的 UTF-8 字节串即被签名的消息。"
    ),
    "signature_encoding": "base64（RFC 4648 标准字母表，含 = 填充）",
    "public_key_encoding": "PEM（SubjectPublicKeyInfo，RFC 5280）",
    "digest": "无（Ed25519 直接对完整消息签名，不做预哈希）",
}


def canonical_json(payload: Any) -> str:
    """canonical-json-v1：键按码点排序、无冗余空白、UTF-8、非 ASCII 不转义。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class KeyUnavailableError(Exception):
    """签名密钥不可用（目录缺失/不可写、活跃指针或私钥文件丢失等）。"""


def _utc_now_stamp() -> str:
    # 与 service.to_canonical 相同的定长 UTC 格式；proof 不依赖 service 以避免循环导入。
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class KeyStore:
    """File-based local Ed25519 key store with rotation support."""

    def __init__(self, key_dir: str) -> None:
        self.key_dir = key_dir
        self._lock = threading.RLock()

    # -- paths --------------------------------------------------------------

    def _private_path(self, key_id: str) -> str:
        return os.path.join(self.key_dir, f"{key_id}.key")

    def _public_path(self, key_id: str) -> str:
        return os.path.join(self.key_dir, f"{key_id}.pub.json")

    @property
    def _active_path(self) -> str:
        return os.path.join(self.key_dir, "active")

    # -- key files ------------------------------------------------------------

    def _list_key_ids(self) -> list[str]:
        try:
            names = os.listdir(self.key_dir)
        except OSError as exc:
            raise KeyUnavailableError(
                f"签名密钥目录不可读：{self.key_dir}（{exc}）"
            ) from exc
        return sorted(
            name[: -len(".pub.json")] for name in names if name.endswith(".pub.json")
        )

    def _active_key_id(self) -> str:
        try:
            with open(self._active_path, "r", encoding="utf-8") as fh:
                key_id = fh.read().strip()
        except OSError as exc:
            raise KeyUnavailableError("活跃签名密钥指针缺失或不可读") from exc
        if not key_id or not os.path.exists(self._public_path(key_id)):
            raise KeyUnavailableError(f"活跃签名密钥 {key_id!r} 的密钥文件缺失")
        return key_id

    @staticmethod
    def _write_atomic(path: str, data: bytes, mode: int = 0o644) -> None:
        tmp = f"{path}.tmp-{uuid.uuid4().hex}"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    def _generate_key(self) -> dict[str, Any]:
        key_id = (
            f"k-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            f"-{uuid.uuid4().hex[:8]}"
        )
        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        info = {
            "key_id": key_id,
            "algorithm": PROOF_ALGORITHM,
            "created_at": _utc_now_stamp(),
            "public_key_pem": public_pem.decode("ascii"),
        }
        try:
            self._write_atomic(self._private_path(key_id), private_pem, 0o600)
            self._write_atomic(
                self._public_path(key_id),
                json.dumps(info, ensure_ascii=False, indent=2).encode("utf-8"),
            )
        except OSError as exc:
            raise KeyUnavailableError(
                f"签名密钥目录不可写：{self.key_dir}（{exc}）"
            ) from exc
        return info

    # -- lifecycle ------------------------------------------------------------

    def ensure_ready(self) -> None:
        """Create the directory and the first key when none exists yet.

        已有密钥但活跃指针缺失时不猜测、不自动修复：让使用方得到明确报错，
        由运维通过轮换接口显式恢复。
        """
        with self._lock:
            try:
                os.makedirs(self.key_dir, exist_ok=True)
            except OSError as exc:
                raise KeyUnavailableError(
                    f"签名密钥目录不可写：{self.key_dir}（{exc}）"
                ) from exc
            if not self._list_key_ids():
                info = self._generate_key()
                self._write_atomic(self._active_path, info["key_id"].encode("ascii"))
            else:
                self._active_key_id()

    # -- signing ----------------------------------------------------------------

    def sign(self, payload: bytes) -> tuple[str, str]:
        """Sign ``payload`` with the active key; return ``(key_id, base64 sig)``."""
        with self._lock:
            key_id = self._active_key_id()
            try:
                with open(self._private_path(key_id), "rb") as fh:
                    private_pem = fh.read()
                private_key = serialization.load_pem_private_key(
                    private_pem, password=None
                )
            except (OSError, ValueError) as exc:
                raise KeyUnavailableError(
                    f"活跃签名密钥 {key_id!r} 的私钥不可用"
                ) from exc
            if not isinstance(private_key, Ed25519PrivateKey):
                raise KeyUnavailableError(f"活跃签名密钥 {key_id!r} 不是 Ed25519 私钥")
            signature = private_key.sign(payload)
            return key_id, base64.b64encode(signature).decode("ascii")

    # -- public info --------------------------------------------------------------

    def _read_public_info(self, key_id: str) -> dict[str, Any] | None:
        try:
            with open(self._public_path(key_id), "r", encoding="utf-8") as fh:
                return json.load(fh)  # type: ignore[no-any-return]
        except (OSError, ValueError):
            return None

    def _with_status(self, info: dict[str, Any]) -> dict[str, Any]:
        try:
            active = self._active_key_id()
        except KeyUnavailableError:
            active = None
        return {
            "key_id": info["key_id"],
            "algorithm": info.get("algorithm", PROOF_ALGORITHM),
            "status": "active" if info["key_id"] == active else "retired",
            "created_at": info.get("created_at", ""),
            "public_key_pem": info["public_key_pem"],
            "encoding": dict(PROOF_ENCODING_RULES),
        }

    def public_key_info(self, key_id: str) -> dict[str, Any] | None:
        """Public key + verification rules for one key id; ``None`` if unknown."""
        with self._lock:
            info = self._read_public_info(key_id)
            return self._with_status(info) if info is not None else None

    def list_keys(self) -> dict[str, Any]:
        """Every stored key (public info only), oldest first, plus the active id."""
        with self._lock:
            try:
                active = self._active_key_id()
            except KeyUnavailableError:
                active = None
            keys = []
            for key_id in self._list_key_ids():
                info = self._read_public_info(key_id)
                if info is not None:
                    keys.append(self._with_status(info))
            keys.sort(key=lambda item: (item["created_at"], item["key_id"]))
            return {"active_key_id": active, "keys": keys}

    # -- rotation -----------------------------------------------------------------

    def rotate(self) -> tuple[dict[str, Any], str | None]:
        """Generate a fresh key and make it active; old keys stay on disk.

        Returns ``(new_active_key_info, previous_active_key_id)``. Old proof
        packages are untouched: they keep their original key id and signature.
        """
        with self._lock:
            try:
                os.makedirs(self.key_dir, exist_ok=True)
            except OSError as exc:
                raise KeyUnavailableError(
                    f"签名密钥目录不可写：{self.key_dir}（{exc}）"
                ) from exc
            try:
                previous = self._active_key_id()
            except KeyUnavailableError:
                previous = None
            info = self._generate_key()
            self._write_atomic(self._active_path, info["key_id"].encode("ascii"))
            return self._with_status(info), previous
