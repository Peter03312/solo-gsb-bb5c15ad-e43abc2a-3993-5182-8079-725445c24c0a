"""Domain logic: version registration, license changes and permission checks."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, NamedTuple

from .database import Database

# Canonical UTC timestamp used for storage and lexicographic comparison in SQL.
# Example: 2026-03-01T08:30:00.000000Z
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_canonical(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("时间必须带时区信息")
    return value.astimezone(timezone.utc).strftime(_TIME_FORMAT)


def parse_canonical(value: str) -> datetime:
    return datetime.strptime(value, _TIME_FORMAT).replace(tzinfo=timezone.utc)


def content_hash(version_id: str, effective_at: str, allowed_uses: list[str]) -> str:
    """Stable hash of a change's semantic content.

    Duplicate submissions are defined as the same change id *and* the same
    semantic content (version, effective instant, allowed-use set). Order of
    the allowed uses is irrelevant; duplicates inside it are ignored.
    """
    payload = {
        "version_id": version_id,
        "effective_at": effective_at,
        "allowed_uses": sorted(set(allowed_uses)),
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# -- domain errors ---------------------------------------------------------


class ServiceError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(ServiceError):
    status_code = 404
    code = "not_found"


class ConflictError(ServiceError):
    status_code = 409
    code = "conflict"


class InvalidTimeError(ServiceError):
    status_code = 422
    code = "invalid_time"


class InvalidIntervalError(ServiceError):
    status_code = 422
    code = "invalid_interval"


# -- serialisation ---------------------------------------------------------


def _change_out(
    row: dict[str, Any], revocation: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "change_id": row["change_id"],
        "version_id": row["version_id"],
        "effective_at": parse_canonical(row["effective_at"]),
        "allowed_uses": list(row["allowed_uses"]),
        "content_hash": row["content_hash"],
        "created_at": parse_canonical(row["created_at"]),
        "revocation": _revocation_out(revocation) if revocation is not None else None,
    }


def _revocation_out(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "revocation_id": row["revocation_id"],
        "change_id": row["change_id"],
        "reason": row["reason"],
        "registered_at": parse_canonical(row["created_at"]),
    }


def _freeze_decision(state: dict[str, Any]) -> str:
    """Serialise an evaluated decision (datetimes -> canonical UTC) to JSON."""
    payload = {
        "allowed": state["allowed"],
        "closure": list(state["closure"]),
        "basis": [
            {
                "version_id": entry["version_id"],
                "change_id": entry["change_id"],
                "effective_at": to_canonical(entry["effective_at"]),
                "allowed_uses": list(entry["allowed_uses"]),
            }
            for entry in state["basis"]
        ],
        "blockers": [
            {
                "version_id": entry["version_id"],
                "reason": entry["reason"],
                "change_id": entry.get("change_id"),
                "effective_at": to_canonical(entry["effective_at"])
                if entry.get("effective_at") is not None
                else None,
                "allowed_uses": list(entry.get("allowed_uses", ())),
            }
            for entry in state["blockers"]
        ],
        "allowed_uses_intersection": list(state["allowed_uses_intersection"]),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _thaw_decision(blob: str) -> dict[str, Any]:
    """Inverse of :func:`_freeze_decision` for stored voucher history."""
    data = json.loads(blob)
    return {
        "allowed": data["allowed"],
        "closure": list(data["closure"]),
        "basis": [
            {
                "version_id": entry["version_id"],
                "change_id": entry["change_id"],
                "effective_at": parse_canonical(entry["effective_at"]),
                "allowed_uses": list(entry["allowed_uses"]),
            }
            for entry in data["basis"]
        ],
        "blockers": [
            {
                "version_id": entry["version_id"],
                "reason": entry["reason"],
                "change_id": entry.get("change_id"),
                "effective_at": parse_canonical(entry["effective_at"])
                if entry.get("effective_at") is not None
                else None,
                "allowed_uses": list(entry.get("allowed_uses", ())),
            }
            for entry in data["blockers"]
        ],
        "allowed_uses_intersection": list(data["allowed_uses_intersection"]),
    }


def _version_out(db: Database, row: dict[str, Any]) -> dict[str, Any]:
    changes = []
    for change in db.list_changes(row["version_id"]):
        revocation = db.get_revocation_of_change(change["change_id"])
        changes.append(_change_out(change, revocation))
    return {
        "version_id": row["version_id"],
        "created_at": parse_canonical(row["created_at"]),
        "note": row["note"],
        "parent_ids": db.get_parents(row["version_id"]),
        "changes": changes,
    }


# -- core service ----------------------------------------------------------


class LicenseService:
    def __init__(self, db: Database) -> None:
        self.db = db

    # -- versions ---------------------------------------------------------

    def register_version(
        self,
        version_id: str | None,
        parent_ids: list[str],
        note: str = "",
    ) -> dict[str, Any]:
        """Register a new version and immutably pin its parent references."""
        version_id = version_id or f"v-{uuid.uuid4().hex}"

        with self.db.lock:
            missing = [pid for pid in parent_ids if self.db.get_version(pid) is None]
            if missing:
                raise NotFoundError(
                    "以下父版本不存在，引用前必须先登记",
                    {"missing_parent_ids": ",".join(missing)},
                )
            if self.db.get_version(version_id) is not None:
                raise ConflictError("版本标识已存在", {"version_id": version_id})

            created = to_canonical(now_utc())
            try:
                self.db.begin()
                self.db.insert_version(version_id, created, note)
                for position, pid in enumerate(parent_ids):
                    self.db.insert_parent(version_id, pid, position)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

            return _version_out(self.db, self.db.get_version(version_id))  # type: ignore[arg-type]

    def get_version(self, version_id: str) -> dict[str, Any]:
        row = self.db.get_version(version_id)
        if row is None:
            raise NotFoundError("版本不存在", {"version_id": version_id})
        return _version_out(self.db, row)

    def list_versions(self) -> list[dict[str, Any]]:
        return [_version_out(self.db, row) for row in self.db.list_versions()]

    def ordered_closure(self, version_id: str) -> list[str]:
        """Return self plus every transitive ancestor, deduplicated, BFS order.

        Parent edges are frozen at registration time, so the graph is a DAG.
        """
        order: list[str] = []
        seen: set[str] = set()
        queue: deque[str] = deque([version_id])
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            order.append(current)
            for parent in self.db.get_parents(current):
                if parent not in seen:
                    queue.append(parent)
        return order

    # -- license changes --------------------------------------------------

    def submit_change(
        self,
        change_id: str | None,
        version_id: str,
        effective_at: datetime,
        allowed_uses: list[str],
    ) -> tuple[dict[str, Any], bool]:
        """Submit a license change.

        Returns ``(change, replayed)``. A repeated submission with the same
        ``change_id`` and identical content is a replay and returns the stored
        result unchanged. Same id with different content, or two different
        changes at the same (version, effective instant), are conflicts.
        """
        if effective_at.tzinfo is None:
            raise InvalidTimeError("生效时刻必须带时区信息")

        change_id = change_id or f"c-{uuid.uuid4().hex}"
        effective = to_canonical(effective_at)
        uses = sorted(set(u.strip() for u in allowed_uses if u.strip()))
        digest = content_hash(version_id, effective, uses)

        with self.db.lock:
            if self.db.get_version(version_id) is None:
                raise NotFoundError("版本不存在，无法为其登记许可变更", {"version_id": version_id})

            existing = self.db.get_change(change_id)
            if existing is not None:
                same = (
                    existing["version_id"] == version_id
                    and existing["effective_at"] == effective
                    and existing["content_hash"] == digest
                )
                if not same:
                    raise ConflictError(
                        "相同变更标识已存在但内容不同",
                        {
                            "change_id": change_id,
                            "submitted_version_id": version_id,
                            "existing_version_id": existing["version_id"],
                            "submitted_effective_at": effective,
                            "existing_effective_at": existing["effective_at"],
                        },
                    )
                # Replays never touch the revocation table: re-submitting a
                # voided change returns the same record but cannot un-void it.
                revocation = self.db.get_revocation_of_change(change_id)
                return _change_out(existing, revocation), True

            twin = self.db.change_at_same_time(version_id, effective)
            if twin is not None and twin["change_id"] != change_id:
                raise ConflictError(
                    "该版本在同一生效时刻已存在不同变更",
                    {
                        "version_id": version_id,
                        "effective_at": effective,
                        "existing_change_id": twin["change_id"],
                        "submitted_change_id": change_id,
                    },
                )

            created = to_canonical(now_utc())
            try:
                self.db.begin()
                self.db.insert_change(change_id, version_id, effective, uses, digest, created)
                self.db.commit()
            except Exception:
                self.db.rollback()
                # Concurrent writers may have won the unique constraint; map
                # both id and (version,time) collisions onto clear conflicts.
                existing = self.db.get_change(change_id)
                if existing is not None:
                    if existing["content_hash"] == digest:
                        revocation = self.db.get_revocation_of_change(change_id)
                        return _change_out(existing, revocation), True
                    raise ConflictError(
                        "相同变更标识已存在但内容不同", {"change_id": change_id}
                    ) from None
                twin = self.db.change_at_same_time(version_id, effective)
                if twin is not None:
                    raise ConflictError(
                        "该版本在同一生效时刻已存在不同变更",
                        {
                            "version_id": version_id,
                            "effective_at": effective,
                            "existing_change_id": twin["change_id"],
                        },
                    ) from None
                raise

            stored = self.db.get_change(change_id)
            assert stored is not None
            return _change_out(stored), False

    def get_change(self, change_id: str) -> dict[str, Any]:
        row = self.db.get_change(change_id)
        if row is None:
            raise NotFoundError("变更不存在", {"change_id": change_id})
        # A revoked change remains fully queryable: its voiding is reported on
        # the same record rather than hiding it.
        revocation = self.db.get_revocation_of_change(change_id)
        return _change_out(row, revocation)

    # -- change revocations ----------------------------------------------

    def revoke_change(
        self,
        change_id: str,
        revocation_id: str | None,
        reason: str,
    ) -> tuple[dict[str, Any], bool]:
        """Void a previously submitted license change.

        A revocation takes effect for every query instant immediately: single
        point checks, timeline segments and previews all ignore the revoked
        change afterwards. The original change row is never deleted. Returns
        ``(receipt, replayed)``.

        Idempotency follows the revocation id: retrying with the same
        ``revocation_id``, target change and reason returns the original
        receipt. Reusing an id with different content, or voiding the same
        change under a different id, is a conflict; an unknown target change
        is ``404``.
        """
        reason = reason.strip()
        if not reason:
            raise ServiceError("作废原因不能为空")
        revocation_id = revocation_id or f"r-{uuid.uuid4().hex}"

        with self.db.lock:
            target = self.db.get_change(change_id)
            if target is None:
                raise NotFoundError(
                    "目标许可变更不存在，无法作废", {"change_id": change_id}
                )

            by_id = self.db.get_revocation(revocation_id)
            by_change = self.db.get_revocation_of_change(change_id)

            if by_id is not None:
                same = (
                    by_id["change_id"] == change_id and by_id["reason"] == reason
                )
                if not same:
                    raise ConflictError(
                        "同一作废标识已存在但内容不同（作废标识不可复用指向不同内容）",
                        {
                            "revocation_id": revocation_id,
                            "submitted_change_id": change_id,
                            "existing_change_id": by_id["change_id"],
                            "submitted_reason": reason,
                            "existing_reason": by_id["reason"],
                        },
                    )
                return _revocation_out(by_id), True

            if by_change is not None:
                raise ConflictError(
                    "该许可变更已被另一作废标识作废，不能重复作废",
                    {
                        "change_id": change_id,
                        "existing_revocation_id": by_change["revocation_id"],
                        "submitted_revocation_id": revocation_id,
                    },
                )

            registered = to_canonical(now_utc())
            try:
                self.db.begin()
                self.db.insert_revocation(revocation_id, change_id, reason, registered)
                self.db.commit()
            except Exception:
                self.db.rollback()
                # Concurrent writers may have won one of the unique
                # constraints; map each race onto the same 409 semantics.
                by_id = self.db.get_revocation(revocation_id)
                if by_id is not None:
                    if by_id["change_id"] == change_id and by_id["reason"] == reason:
                        return _revocation_out(by_id), True
                    raise ConflictError(
                        "同一作废标识已存在但内容不同（作废标识不可复用指向不同内容）",
                        {"revocation_id": revocation_id},
                    ) from None
                by_change = self.db.get_revocation_of_change(change_id)
                if by_change is not None:
                    raise ConflictError(
                        "该许可变更已被另一作废标识作废，不能重复作废",
                        {
                            "change_id": change_id,
                            "existing_revocation_id": by_change["revocation_id"],
                        },
                    ) from None
                raise

            stored = self.db.get_revocation(revocation_id)
            assert stored is not None
            return _revocation_out(stored), False

    def get_revocation(self, revocation_id: str) -> dict[str, Any]:
        row = self.db.get_revocation(revocation_id)
        if row is None:
            raise NotFoundError(
                "作废回执不存在", {"revocation_id": revocation_id}
            )
        return _revocation_out(row)

    # -- permission query -------------------------------------------------

    def check_permission(self, version_id: str, use: str, at: datetime) -> dict[str, Any]:
        """Evaluate whether ``use`` is permitted for ``version_id`` at ``at``.

        For the queried version and every ancestor, take the latest change
        effective at or before ``at``; the permitted uses are the intersection
        over them. Any version without an effective change, or whose latest
        change does not include the requested use, blocks the request.
        """
        if at.tzinfo is None:
            raise InvalidTimeError("查询时刻必须带时区信息")
        use = use.strip()
        if not use:
            raise ServiceError("用途不能为空")

        if self.db.get_version(version_id) is None:
            raise NotFoundError("版本不存在", {"version_id": version_id})

        at_canonical = to_canonical(at)
        closure = self.ordered_closure(version_id)

        basis: list[dict[str, Any]] = []
        blockers: list[dict[str, Any]] = []
        intersection: set[str] | None = None
        missing_license = False

        for vid in closure:
            change = self.db.latest_change(vid, at_canonical)
            if change is None:
                missing_license = True
                blockers.append(
                    {"version_id": vid, "reason": "no_valid_license"}
                )
                continue

            allowed = set(change["allowed_uses"])
            basis.append(
                {
                    "version_id": vid,
                    "change_id": change["change_id"],
                    "effective_at": parse_canonical(change["effective_at"]),
                    "allowed_uses": sorted(allowed),
                }
            )
            intersection = allowed if intersection is None else intersection & allowed
            if use not in allowed:
                blockers.append(
                    {
                        "version_id": vid,
                        "reason": "use_not_allowed",
                        "change_id": change["change_id"],
                        "effective_at": parse_canonical(change["effective_at"]),
                        "allowed_uses": sorted(allowed),
                    }
                )

        # When some version has no effective license at all, no intersection
        # is meaningful (the request is denied regardless).
        if missing_license:
            result_intersection: list[str] = []
        else:
            result_intersection = sorted(intersection) if intersection is not None else []
        return {
            "version_id": version_id,
            "use": use,
            "at": at.astimezone(timezone.utc),
            "allowed": not blockers,
            "closure": closure,
            "basis": basis,
            "blockers": blockers,
            "allowed_uses_intersection": result_intersection,
        }

    # -- permission timeline (interval segmentation) ----------------------

    def check_permission_timeline(
        self,
        version_id: str,
        use: str,
        start: datetime,
        end: datetime,
    ) -> dict[str, Any]:
        """Slice the half-open interval ``[start, end)`` into permission segments.

        All reads come from one pinned snapshot (the same mechanism as the
        change preview), so the ancestor closure and every change seen here
        belong to a single consistent view. Segment boundaries are the
        effective instants of the closure's non-revoked changes strictly
        inside the interval; a change exactly at ``start`` applies from the
        first segment on, a change exactly at ``end`` is not counted. Revoked
        changes are ignored for every segment. Segments are only split where
        the basis or the blocking information changes — adjacent identical
        segments are merged.
        """
        if start.tzinfo is None or end.tzinfo is None:
            raise InvalidTimeError("起止时刻必须带时区信息")
        use = use.strip()
        if not use:
            raise ServiceError("用途不能为空")

        start_utc = start.astimezone(timezone.utc)
        end_utc = end.astimezone(timezone.utc)
        if not start_utc < end_utc:
            raise InvalidIntervalError(
                "开始时刻必须严格早于结束时刻（半开区间 [start, end) 不能为空或倒置）",
                {
                    "start": to_canonical(start_utc),
                    "end": to_canonical(end_utc),
                },
            )

        with self.db.lock:
            snapshot = self._capture_snapshot()
        if version_id not in snapshot.versions:
            raise NotFoundError("版本不存在", {"version_id": version_id})

        start_c = to_canonical(start_utc)
        end_c = to_canonical(end_utc)
        closure = snapshot.closure_from(version_id)

        interior: set[str] = set()
        for vid in closure:
            for change in snapshot.changes.get(vid, ()):
                if change.change_id in snapshot.revoked_change_ids:
                    # Revoked changes neither split segments nor set policy.
                    continue
                if start_c < change.effective_at < end_c:
                    interior.add(change.effective_at)
        edges = [start_c, *sorted(interior), end_c]

        segments: list[dict[str, Any]] = []
        open_segment: tuple[tuple[Any, ...], dict[str, Any], str] | None = None
        for index in range(len(edges) - 1):
            seg_start = edges[index]
            # The state is constant within [seg_start, next edge): only a
            # change can alter it, and every in-interval change is an edge.
            state = _evaluate(snapshot, version_id, use, seg_start, None)
            key = _segment_state_key(state)
            if open_segment is not None and open_segment[0] == key:
                # Identical basis and blockers: extend the previous segment.
                continue
            if open_segment is not None:
                segments.append(
                    _segment_payload(open_segment[2], seg_start, open_segment[1])
                )
            open_segment = (key, state, seg_start)
        assert open_segment is not None  # start < end guarantees >= 1 segment
        segments.append(_segment_payload(open_segment[2], end_c, open_segment[1]))

        return {
            "version_id": version_id,
            "use": use,
            "start": start_utc,
            "end": end_utc,
            "closure": closure,
            "segments": segments,
        }

    # -- permission vouchers (traceable frozen decisions) -----------------

    def issue_voucher(
        self,
        voucher_id: str | None,
        version_id: str,
        use: str,
        at: datetime,
    ) -> tuple[dict[str, Any], bool]:
        """Evaluate a permission decision and persist it as a frozen voucher.

        The first request for ``voucher_id`` applies the *existing* decision
        rules inside one write transaction against a single consistent
        snapshot, and stores the server-generated registration time together
        with the complete ancestor closure, basis, blockers and allowed-use
        intersection — allow and deny alike are recorded. Evaluation and
        storage are atomic: any failure rolls back and leaves no partial row.

        Stored vouchers are immutable history. A retry with the same voucher
        id, version, trimmed use and UTC-normalised instant returns the
        original voucher untouched; later license changes or revocations
        cannot rewrite it. Reusing the id against different inputs is a
        conflict. Unknown version, empty use or naive time error out before
        any row is written.
        """
        if at.tzinfo is None:
            raise InvalidTimeError("判定时刻必须带时区信息")
        use = use.strip()
        if not use:
            raise ServiceError("用途不能为空")
        voucher_id = voucher_id or f"p-{uuid.uuid4().hex}"
        at_canonical = to_canonical(at)

        with self.db.lock:
            existing = self.db.get_voucher(voucher_id)
            if existing is not None:
                same = (
                    existing["version_id"] == version_id
                    and existing["use_name"] == use
                    and existing["at_value"] == at_canonical
                )
                if not same:
                    raise ConflictError(
                        "同一凭证标识已存在但输入不同（凭证标识不可复用指向不同判定）",
                        {
                            "voucher_id": voucher_id,
                            "submitted_version_id": version_id,
                            "existing_version_id": existing["version_id"],
                            "submitted_use": use,
                            "existing_use": existing["use_name"],
                            "submitted_at": at_canonical,
                            "existing_at": existing["at_value"],
                        },
                    )
                return self._voucher_out(existing), True

            try:
                # BEGIN IMMEDIATE pins both a write lock and one snapshot: the
                # version lookup, closure evaluation and insert commit as one
                # atomic unit, so concurrent issuers cannot interleave.
                self.db.begin()
                if self.db.get_version(version_id) is None:
                    raise NotFoundError(
                        "版本不存在，无法签发判定凭证", {"version_id": version_id}
                    )
                snapshot = self._capture_snapshot(manage_transaction=False)
                state = _evaluate(snapshot, version_id, use, at_canonical, None)
                registered = to_canonical(now_utc())
                self.db.insert_voucher(
                    voucher_id=voucher_id,
                    version_id=version_id,
                    use_name=use,
                    at_value=at_canonical,
                    registered_at=registered,
                    allowed=state["allowed"],
                    decision_json=_freeze_decision(state),
                )
                self.db.commit()
            except Exception:
                self.db.rollback()
                # A concurrent writer may have won the same primary key: map
                # the race onto replay/conflict exactly like a sequential call.
                raced = self.db.get_voucher(voucher_id)
                if raced is not None:
                    same = (
                        raced["version_id"] == version_id
                        and raced["use_name"] == use
                        and raced["at_value"] == at_canonical
                    )
                    if same:
                        return self._voucher_out(raced), True
                    raise ConflictError(
                        "同一凭证标识已存在但输入不同（凭证标识不可复用指向不同判定）",
                        {
                            "voucher_id": voucher_id,
                            "submitted_version_id": version_id,
                            "existing_version_id": raced["version_id"],
                        },
                    ) from None
                raise

            stored = self.db.get_voucher(voucher_id)
            assert stored is not None
            return self._voucher_out(stored), False

    def get_voucher(self, voucher_id: str) -> dict[str, Any]:
        """Return the frozen first-saved decision for a voucher id."""
        row = self.db.get_voucher(voucher_id)
        if row is None:
            raise NotFoundError("判定凭证不存在", {"voucher_id": voucher_id})
        return self._voucher_out(row)

    @staticmethod
    def _voucher_out(row: dict[str, Any]) -> dict[str, Any]:
        decision = _thaw_decision(row["decision_json"])
        return {
            "voucher_id": row["voucher_id"],
            "version_id": row["version_id"],
            "use": row["use_name"],
            "at": parse_canonical(row["at_value"]),
            "registered_at": parse_canonical(row["registered_at"]),
            **decision,
        }

    # -- change preview (no writes) ---------------------------------------

    def preview_change(
        self,
        *,
        change_id: str | None,
        version_id: str,
        effective_at: datetime,
        allowed_uses: list[str],
        use: str,
        at: datetime,
    ) -> dict[str, Any]:
        """Dry-run a change without persisting it.

        Evaluates the given ``use`` at query time ``at`` for the target
        version and every descendant twice — once on the current snapshot and
        once as if the proposed change were committed — and returns only the
        versions whose allow/deny status flips, with before/after blockers.

        Conflict semantics mirror :meth:`submit_change`: unknown version ->
        404; same change id with different content, or a different change at
        the same (version, effective instant) -> 409; same id and content is a
        replay with no effect. All reads come from one pinned read snapshot so
        concurrent commits cannot interleave into the evaluation.
        """
        if effective_at.tzinfo is None:
            raise InvalidTimeError("生效时刻必须带时区信息")
        if at.tzinfo is None:
            raise InvalidTimeError("查询时刻必须带时区信息")
        use = use.strip()
        if not use:
            raise ServiceError("用途不能为空")

        effective = to_canonical(effective_at)
        uses = sorted(set(u.strip() for u in allowed_uses if u.strip()))
        change_id = change_id or f"c-{uuid.uuid4().hex}"
        digest = content_hash(version_id, effective, uses)

        with self.db.lock:
            if self.db.get_version(version_id) is None:
                raise NotFoundError("版本不存在，无法为其预演许可变更", {"version_id": version_id})

            existing = self.db.get_change(change_id)
            replayed = False
            if existing is not None:
                same = (
                    existing["version_id"] == version_id
                    and existing["effective_at"] == effective
                    and existing["content_hash"] == digest
                )
                if not same:
                    raise ConflictError(
                        "相同变更标识已存在但内容不同",
                        {
                            "change_id": change_id,
                            "submitted_version_id": version_id,
                            "existing_version_id": existing["version_id"],
                            "submitted_effective_at": effective,
                            "existing_effective_at": existing["effective_at"],
                        },
                    )
                replayed = True
            else:
                twin = self.db.change_at_same_time(version_id, effective)
                if twin is not None and twin["change_id"] != change_id:
                    raise ConflictError(
                        "该版本在同一生效时刻已存在不同变更",
                        {
                            "version_id": version_id,
                            "effective_at": effective,
                            "existing_change_id": twin["change_id"],
                            "submitted_change_id": change_id,
                        },
                    )
            snapshot = self._capture_snapshot()

        at_canonical = to_canonical(at)
        scope = snapshot.descendants_of(version_id)
        override = None if replayed else EffectiveChange(
            change_id=change_id,
            version_id=version_id,
            effective_at=effective,
            allowed_uses=uses,
        )

        impacted: list[dict[str, Any]] = []
        for node in scope:
            before = _evaluate(snapshot, node, use, at_canonical, None)
            after = (
                before
                if override is None
                else _evaluate(snapshot, node, use, at_canonical, override)
            )
            if before["allowed"] == after["allowed"]:
                # Query before the effective instant, a later stored change
                # already covering the proposal, or simply no difference.
                continue
            impacted.append(
                {
                    "version_id": node,
                    "closure": before["closure"],
                    "before_allowed": before["allowed"],
                    "after_allowed": after["allowed"],
                    "before_blockers": before["blockers"],
                    "after_blockers": after["blockers"],
                    "before_basis": before["basis"],
                    "after_basis": after["basis"],
                    "before_allowed_uses_intersection": before["allowed_uses_intersection"],
                    "after_allowed_uses_intersection": after["allowed_uses_intersection"],
                }
            )

        return {
            "replayed": replayed,
            "change": {
                "change_id": change_id,
                "version_id": version_id,
                "effective_at": parse_canonical(effective),
                "allowed_uses": uses,
            },
            "query": {"use": use, "at": at.astimezone(timezone.utc)},
            "scope": scope,
            "impacted_versions": impacted,
        }

    def _capture_snapshot(self, *, manage_transaction: bool = True) -> Snapshot:
        """Pin one consistent read snapshot of versions, edges and changes.

        Runs inside the caller's db lock. With ``manage_transaction`` it opens
        a deferred read transaction (WAL): the first SELECT pins a consistent
        snapshot that stays stable until the rollback, and taking no write lock
        keeps previews read-only. When ``manage_transaction`` is false the
        caller already owns an open write transaction (voucher issuing): all
        SELECTs then share that transaction's snapshot and its write lock, so
        the evaluation and the subsequent insert are atomic against every
        other writer.
        """
        if manage_transaction:
            self.db.begin_read()
        try:
            versions = {row["version_id"] for row in self.db.list_versions()}
            edges = self.db.all_parent_edges()
            revoked = set(self.db.list_revoked_change_ids())
            changes: dict[str, list[EffectiveChange]] = {}
            rows = self.db.query_all(
                "SELECT * FROM license_changes ORDER BY version_id, effective_at, change_id"
            )
            for row in rows:
                changes.setdefault(row["version_id"], []).append(
                    EffectiveChange(
                        change_id=row["change_id"],
                        version_id=row["version_id"],
                        effective_at=row["effective_at"],
                        allowed_uses=list(row["allowed_uses"]),
                    )
                )
            return Snapshot(
                versions=versions,
                edges=edges,
                changes=changes,
                revoked_change_ids=revoked,
            )
        finally:
            if manage_transaction:
                self.db.rollback()


# -- immutable in-memory snapshot ------------------------------------------


class EffectiveChange(NamedTuple):
    change_id: str
    version_id: str
    effective_at: str  # canonical UTC
    allowed_uses: list[str]


@dataclass(frozen=True)
class Snapshot:
    versions: set[str]
    edges: list[tuple[str, str]]  # (child, parent) in registration order
    changes: dict[str, list[EffectiveChange]]  # keyed by version, time-sorted
    revoked_change_ids: set[str] = frozenset()  # type: ignore[assignment]
    parents_map: dict[str, list[str]] = field(default_factory=dict)
    children_map: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        parents: dict[str, list[str]] = {vid: [] for vid in self.versions}
        children: dict[str, set[str]] = {vid: set() for vid in self.versions}
        for child, parent in self.edges:  # edges arrive ordered by position
            parents.setdefault(child, []).append(parent)
            children.setdefault(parent, set()).add(child)
        object.__setattr__(self, "parents_map", parents)
        object.__setattr__(
            self, "children_map", {vid: sorted(kids) for vid, kids in children.items()}
        )

    def closure_from(self, version_id: str) -> list[str]:
        """Self plus all ancestors, BFS, deduplicated (diamond-safe)."""
        parents = self.parents_map
        order: list[str] = []
        seen = {version_id}
        queue = deque([version_id])
        while queue:
            current = queue.popleft()
            order.append(current)
            for parent in parents.get(current, []):
                if parent not in seen:
                    seen.add(parent)
                    queue.append(parent)
        return order

    def descendants_of(self, version_id: str) -> list[str]:
        """The version itself plus every transitive descendant, deduplicated."""
        children = self.children_map
        order: list[str] = []
        seen = {version_id}
        queue = deque([version_id])
        while queue:
            current = queue.popleft()
            order.append(current)
            for child in children.get(current, []):
                if child not in seen:
                    seen.add(child)
                    queue.append(child)
        return order

    def latest_change(
        self,
        version_id: str,
        at_canonical: str,
        override: EffectiveChange | None,
    ) -> EffectiveChange | None:
        """Latest change effective at or before the query instant.

        ``override`` is the hypothetical change for exactly its target
        version. If it is not effective yet, or a stored change is effective
        later than it (already covering that instant), the stored latest
        change wins — exactly matching the "latest effective change" rule
        applied after a real commit.
        """
        stored: EffectiveChange | None = None
        for change in self.changes.get(version_id, ()):  # time-sorted
            if change.change_id in self.revoked_change_ids:
                # A voiding applies at every query instant: skipped entirely.
                continue
            if change.effective_at <= at_canonical:
                stored = change
            else:
                break
        if override is None or override.version_id != version_id:
            return stored
        if override.effective_at > at_canonical:
            return stored
        if stored is not None and stored.effective_at > override.effective_at:
            return stored
        return override


def _evaluate(
    snapshot: Snapshot,
    version_id: str,
    use: str,
    at_canonical: str,
    override: EffectiveChange | None,
) -> dict[str, Any]:
    """Pure counterpart of LicenseService.check_permission on a snapshot."""
    closure = snapshot.closure_from(version_id)
    basis: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    intersection: set[str] | None = None
    missing_license = False

    for vid in closure:
        change = snapshot.latest_change(vid, at_canonical, override)
        if change is None:
            missing_license = True
            blockers.append({"version_id": vid, "reason": "no_valid_license"})
            continue

        allowed = set(change.allowed_uses)
        basis.append(
            {
                "version_id": vid,
                "change_id": change.change_id,
                "effective_at": parse_canonical(change.effective_at),
                "allowed_uses": sorted(allowed),
            }
        )
        intersection = allowed if intersection is None else intersection & allowed
        if use not in allowed:
            blockers.append(
                {
                    "version_id": vid,
                    "reason": "use_not_allowed",
                    "change_id": change.change_id,
                    "effective_at": parse_canonical(change.effective_at),
                    "allowed_uses": sorted(allowed),
                }
            )

    if missing_license:
        result_intersection: list[str] = []
    else:
        result_intersection = sorted(intersection) if intersection is not None else []
    return {
        "allowed": not blockers,
        "closure": closure,
        "basis": basis,
        "blockers": blockers,
        "allowed_uses_intersection": result_intersection,
    }


def _segment_state_key(state: dict[str, Any]) -> tuple[Any, ...]:
    """Hashable identity of a segment: allowed flag, basis and blockers.

    Two adjacent slices with equal keys carry the same 判定依据 and 阻断信息
    and must be merged into one continuous segment.
    """
    basis_key = tuple(
        (
            entry["version_id"],
            entry["change_id"],
            to_canonical(entry["effective_at"]),
            tuple(entry["allowed_uses"]),
        )
        for entry in state["basis"]
    )
    blocker_key = tuple(
        (
            entry["version_id"],
            entry["reason"],
            entry.get("change_id"),
            to_canonical(entry["effective_at"])
            if entry.get("effective_at") is not None
            else None,
            tuple(entry.get("allowed_uses", ())),
        )
        for entry in state["blockers"]
    )
    return (
        state["allowed"],
        basis_key,
        blocker_key,
        tuple(state["allowed_uses_intersection"]),
    )


def _segment_payload(start_c: str, end_c: str, state: dict[str, Any]) -> dict[str, Any]:
    return {
        "start": parse_canonical(start_c),
        "end": parse_canonical(end_c),
        "allowed": state["allowed"],
        "basis": state["basis"],
        "blockers": state["blockers"],
        "allowed_uses_intersection": state["allowed_uses_intersection"],
    }
