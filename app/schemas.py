"""Pydantic request/response models for the HTTP API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _ensure_aware(value: datetime) -> datetime:
    """Reject naive datetimes; normalise any aware value to UTC."""
    if value.tzinfo is None:
        raise ValueError(
            "时间必须带时区信息，例如 2026-01-01T00:00:00Z 或 2026-01-01T08:00:00+08:00"
        )
    return value.astimezone(timezone.utc)


def _normalise_uses(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    for raw in values:
        use = raw.strip()
        if not use:
            raise ValueError("allowed_uses 不能包含空字符串")
        if use not in cleaned:
            cleaned.append(use)
    return cleaned


# -- requests --------------------------------------------------------------


class VersionCreateRequest(BaseModel):
    version_id: str | None = Field(
        default=None, min_length=1, max_length=128, description="版本标识；省略时自动生成 UUID"
    )
    parent_ids: list[str] = Field(
        default_factory=list, description="固定引用的已存在父版本（注册后不可修改）"
    )
    note: str = Field(default="", max_length=512)

    @field_validator("parent_ids")
    @classmethod
    def _unique_parents(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in values:
            pid = raw.strip()
            if not pid:
                raise ValueError("parent_ids 不能包含空字符串")
            if pid not in cleaned:
                cleaned.append(pid)
        return cleaned


class LicenseChangeRequest(BaseModel):
    change_id: str | None = Field(
        default=None, min_length=1, max_length=128, description="变更标识；省略时自动生成 UUID"
    )
    version_id: str = Field(min_length=1, description="变更所属的已登记版本")
    effective_at: datetime = Field(description="UTC 生效时刻（必须带时区）")
    allowed_uses: list[str] = Field(description="该次变更后允许的用途全集（按全集覆盖）")

    _check_time = field_validator("effective_at")(_ensure_aware)

    @field_validator("allowed_uses")
    @classmethod
    def _uses(cls, values: list[str]) -> list[str]:
        return _normalise_uses(values)


# -- responses -------------------------------------------------------------


class VersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version_id: str
    created_at: datetime
    note: str
    parent_ids: list[str]
    changes: list["LicenseChangeResponse"]


class LicenseChangeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    change_id: str
    version_id: str
    effective_at: datetime
    allowed_uses: list[str]
    content_hash: str
    created_at: datetime
    revocation: "RevocationReceipt | None" = Field(
        default=None, description="该变更已作废时的作废回执；未作废时为 null"
    )


class ChangeRevocationRequest(BaseModel):
    change_id: str = Field(min_length=1, description="待作废的原许可变更标识")
    revocation_id: str | None = Field(
        default=None, min_length=1, max_length=128, description="唯一作废标识；省略时自动生成 UUID"
    )
    reason: str = Field(min_length=1, max_length=1024, description="作废原因")

    @field_validator("reason")
    @classmethod
    def _reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reason 不能为空白字符串")
        return value


class RevocationReceipt(BaseModel):
    """作废回执：原标识、作废标识、原因与登记时间，可按作废标识追溯。"""

    revocation_id: str
    change_id: str
    reason: str
    registered_at: datetime


class RevocationResponse(BaseModel):
    replayed: bool = Field(description="同一作废标识与内容重试时为 true，返回原回执")
    receipt: RevocationReceipt


class BasisEntry(BaseModel):
    version_id: str
    change_id: str
    effective_at: datetime
    allowed_uses: list[str]


class BlockerEntry(BaseModel):
    version_id: str
    reason: Literal["no_valid_license", "use_not_allowed"]
    change_id: str | None = None
    effective_at: datetime | None = None
    allowed_uses: list[str] = Field(default_factory=list)


class PermissionResponse(BaseModel):
    version_id: str
    use: str
    at: datetime
    allowed: bool
    closure: list[str] = Field(description="自身及全部祖先（去重、广度优先）")
    basis: list[BasisEntry] = Field(default_factory=list, description="各版本在该时刻所依据的最近变更")
    blockers: list[BlockerEntry] = Field(default_factory=list)
    allowed_uses_intersection: list[str] = Field(default_factory=list)


class PermissionSegment(BaseModel):
    """One continuous slice of a permission timeline.

    Within ``[start, end)`` the evaluation is constant: ``basis`` and
    ``blockers`` are exactly what the single-instant check would report at
    any instant inside the slice.
    """

    start: datetime = Field(description="片段起点（含）")
    end: datetime = Field(description="片段终点（不含）")
    allowed: bool
    basis: list[BasisEntry] = Field(default_factory=list, description="片段内各版本所依据的最近变更")
    blockers: list[BlockerEntry] = Field(default_factory=list, description="片段内全部阻断版本与原因")
    allowed_uses_intersection: list[str] = Field(default_factory=list)


class PermissionTimelineResponse(BaseModel):
    version_id: str
    use: str
    start: datetime = Field(description="区间起点（含）")
    end: datetime = Field(description="区间终点（不含）")
    closure: list[str] = Field(description="自身及全部祖先（去重、广度优先）")
    segments: list[PermissionSegment] = Field(
        description=(
            "半开区间 [start, end) 切出的连续、无重叠片段；"
            "仅在判定依据或阻断信息变化时分段，相邻相同片段已合并"
        )
    )


class CreateResponse(BaseModel):
    """Response wrapper that reports whether a submission was replayed."""

    replayed: bool
    change: LicenseChangeResponse | None = None
    version: VersionResponse | None = None


# -- permission vouchers ---------------------------------------------------


class VoucherIssueRequest(BaseModel):
    voucher_id: str | None = Field(
        default=None, min_length=1, max_length=128, description="唯一凭证标识；省略时自动生成 UUID"
    )
    version_id: str = Field(min_length=1, description="已登记的数据集版本")
    use: str = Field(min_length=1, description="拟申请的用途（去首尾空格后判定与留痕）")
    at: datetime = Field(description="带时区的判定时刻，服务统一换算为 UTC 归一化")

    _check_time = field_validator("at")(_ensure_aware)

    @field_validator("use")
    @classmethod
    def _use(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("use 不能为空白字符串")
        return value


class VoucherDecision(BaseModel):
    """一次用途判定的不可变凭证：首次保存时的完整判定快照。"""

    voucher_id: str = Field(description="唯一凭证标识")
    version_id: str
    use: str
    at: datetime = Field(description="换算为 UTC 后的判定时刻")
    registered_at: datetime = Field(description="凭证登记时间（服务按 UTC 生成）")
    allowed: bool
    closure: list[str] = Field(description="首次判定时的自身及全部祖先（去重、广度优先）")
    basis: list[BasisEntry] = Field(
        default_factory=list, description="首次判定时各版本所依据的最近变更"
    )
    blockers: list[BlockerEntry] = Field(
        default_factory=list, description="首次判定时的全部阻断版本与原因（允许时为空）"
    )
    allowed_uses_intersection: list[str] = Field(default_factory=list)


class VoucherResponse(BaseModel):
    replayed: bool = Field(description="同标识与同输入重试时为 true，返回首次保存的原凭证")
    voucher: VoucherDecision


# -- signed voucher proof packages -----------------------------------------


class ProofBasisEntry(BaseModel):
    """首次判定快照中某版本所依据的变更（签名字段，UTC 文本时间）。"""

    version_id: str
    change_id: str
    effective_at: str
    allowed_uses: list[str]


class ProofBlockerEntry(BaseModel):
    """首次判定快照中的一条阻断原因（签名字段，UTC 文本时间）。"""

    version_id: str
    reason: Literal["no_valid_license", "use_not_allowed"]
    change_id: str | None = None
    effective_at: str | None = None
    allowed_uses: list[str] = Field(default_factory=list)


class ProofPayload(BaseModel):
    """签名覆盖的首次判定完整快照；任一字段被篡改都无法通过验签。"""

    format_version: int = Field(description="证明包/载荷格式版本（签名字段）")
    voucher_id: str = Field(description="凭证标识（签名字段）")
    version_id: str = Field(description="判定版本（签名字段）")
    use: str = Field(description="归一化后的用途（签名字段）")
    at: str = Field(description="判定时刻，UTC 文本 YYYY-MM-DDTHH:MM:SS.ffffffZ（签名字段）")
    registered_at: str = Field(description="凭证登记时刻（首次判定服务生成，签名字段）")
    allowed: bool = Field(description="首次判定结果：允许/拒绝（签名字段）")
    closure: list[str] = Field(description="首次判定的祖先闭包（顺序敏感，签名字段）")
    basis: list[ProofBasisEntry] = Field(description="首次判定的全部依据（顺序敏感，签名字段）")
    blockers: list[ProofBlockerEntry] = Field(description="首次判定的全部阻断原因（顺序敏感，签名字段）")
    allowed_uses_intersection: list[str] = Field(
        description="首次判定的用途交集（顺序敏感，签名字段）"
    )


class ProofSignature(BaseModel):
    algorithm: str = Field(description="签名算法：Ed25519（RFC 8032）")
    jws_alg: str = Field(description="JWS 头 alg：EdDSA（RFC 8037）")
    key_id: str = Field(description="签发所用密钥标识，可据此取回对应公钥")
    protected_header: dict[str, str]
    protected: str = Field(description="BASE64URL(UTF8(保护头 JSON))")
    payload: str = Field(description="BASE64URL(规范 JSON 载荷)，与 payload 重编码逐字节一致")
    signature: str = Field(description="BASE64URL(Ed25519 签名)")
    compact_serialization: str = Field(
        description="JWS 紧凑序列化：protected.payload.signature，可直接离线验签"
    )
    public_key_pem: str = Field(description="签发公钥（SPKI PEM），便于完全离线核验")
    public_key_jwk: dict[str, str] = Field(description="签发公钥（RFC 8037 OKP JWK）")


class ProofEncodingRules(BaseModel):
    format: str
    jws_compact_serialization: str
    protected_header_json: str
    payload_encoding: str
    base64url: str
    signing_input: str
    signature_scheme: str
    timestamp_format: str
    covered_fields: list[str] = Field(
        description="签名覆盖的全部字段；任一字段被篡改都无法通过验签"
    )


class ProofVerification(BaseModel):
    encoding: ProofEncodingRules = Field(description="明确的验签编码规则（离线审计方照此重算）")
    public_key_url: str = Field(description="按密钥标识取公钥的路径模板")
    public_keys_url: str = Field(description="列出全部保留公钥（含轮换前旧公钥）的路径")


class ProofPackage(BaseModel):
    """交给离线审计方的固定证明包；重复/并发导出返回同一内容。"""

    format_version: int
    voucher_id: str
    payload: ProofPayload
    signature: ProofSignature
    verification: ProofVerification
    exported_at: str = Field(
        description="首次导出固化时间（UTC 文本）；不属于签名载荷，旧包不会因此重签"
    )


class ProofExportResponse(BaseModel):
    replayed: bool = Field(description="重复/并发导出时为 true，返回已固化的同一证明包")
    proof: ProofPackage


# -- signing keys -----------------------------------------------------------


class PublicKeyResponse(BaseModel):
    key_id: str
    algorithm: str = Field(description="Ed25519（RFC 8032）")
    jws_alg: str = Field(description="EdDSA（RFC 8037）")
    curve: str
    created_at: str = Field(description="密钥生成时间（UTC 文本）")
    active: bool = Field(description="是否为当前活跃签发密钥")
    public_key_pem: str = Field(description="SPKI PEM 公钥")
    public_key_jwk: dict[str, str] = Field(description="RFC 8037 OKP JWK 公钥")


class PublicKeyListResponse(BaseModel):
    active_key_id: str | None = None
    keys: list[PublicKeyResponse]


class KeyRotationResponse(BaseModel):
    replayed: bool = Field(default=False, description="始终为 false：每次轮换都生成全新密钥")
    previous_key_id: str | None = Field(description="轮换前的活跃密钥标识（旧证明包仍用其验签）")
    key: PublicKeyResponse


# -- change preview --------------------------------------------------------


class PreviewChangeRequest(BaseModel):
    change_id: str | None = Field(
        default=None, min_length=1, max_length=128, description="变更标识；省略时自动生成 UUID"
    )
    version_id: str = Field(min_length=1, description="预演变更所属的已登记版本")
    effective_at: datetime = Field(description="UTC 生效时刻（必须带时区）")
    allowed_uses: list[str] = Field(description="假设提交的变更允许用途全集（按全集覆盖）")
    use: str = Field(min_length=1, description="待判定的用途")
    at: datetime = Field(description="带时区的查询时刻")

    _check_effective_time = field_validator("effective_at")(_ensure_aware)
    _check_query_time = field_validator("at")(_ensure_aware)

    @field_validator("allowed_uses")
    @classmethod
    def _uses(cls, values: list[str]) -> list[str]:
        return _normalise_uses(values)

    @field_validator("use")
    @classmethod
    def _use(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("use 不能为空字符串")
        return value


class PreviewChangeStub(BaseModel):
    change_id: str
    version_id: str
    effective_at: datetime
    allowed_uses: list[str]


class PreviewQuery(BaseModel):
    use: str
    at: datetime


class ImpactedVersion(BaseModel):
    version_id: str
    closure: list[str] = Field(description="判定该版本时用到的自身及全部祖先（去重、广度优先）")
    before_allowed: bool = Field(description="现状（假设提交前）的允许状态")
    after_allowed: bool = Field(description="假设该变更提交后的允许状态")
    before_blockers: list[BlockerEntry] = Field(default_factory=list, description="提交前全部阻断版本与原因")
    after_blockers: list[BlockerEntry] = Field(default_factory=list, description="提交后全部阻断版本与原因")
    before_basis: list[BasisEntry] = Field(default_factory=list)
    after_basis: list[BasisEntry] = Field(default_factory=list)
    before_allowed_uses_intersection: list[str] = Field(default_factory=list)
    after_allowed_uses_intersection: list[str] = Field(default_factory=list)


class PreviewResponse(BaseModel):
    replayed: bool = Field(description="相同标识与内容已存在时为 true，预演结果等同于现状（无影响）")
    change: PreviewChangeStub
    query: PreviewQuery
    scope: list[str] = Field(description="目标版本及其全部后代（去重、广度优先）；预演仅在该集合内计算")
    impacted_versions: list[ImpactedVersion] = Field(
        default_factory=list,
        description="允许状态发生变化的版本（含前后判定与阻断原因）；查询早于生效时刻或被更晚变更覆盖时为空",
    )


class ErrorDetail(BaseModel):
    error: str
    message: str
    details: dict[str, str | None] = Field(default_factory=dict)
