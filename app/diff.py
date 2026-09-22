"""审查版本对比：对齐两个已保存项目的分析结果，报告依赖与结论差异。

对比语义：

* 以 ``name@version``（分析结果中的 ``id``）对齐两个项目的依赖结论；
* 报告 **新增 / 移除 / 许可证变化 / 结论变化** 四类差异；
* 当前版本中结论为 ``deny`` / ``review`` 而基线中不是冲突（或根本不存在）的包，
  记入 ``new_conflicts``，并携带**当前制品、触发规则与最短依赖路径**；
* 反向消失的冲突记入 ``resolved_conflicts``（被移除、变为兼容或已确认例外）；
* 多制品（``mode == "multi"``）结果**按制品名分别对比**，制品本身的新增 / 移除
  单独列出；单制品与多制品结果之间无法对比（抛出 :class:`DiffError`）。

输入是 :func:`app.analyzer.analyze` 的结果字典（例外已生效），
输出为可 JSON 序列化的对比报告。
"""
from __future__ import annotations

from typing import Dict, List, Optional

#: 视为"冲突（待处理）"的结论
CONFLICT_VERDICTS = ("deny", "review")

_VERDICT_ORDER = {"deny": 0, "review": 1, "exception": 2, "allow": 3}


class DiffError(ValueError):
    """两个分析结果无法对比（如单制品 vs 多制品）。"""


def _license_signature(entry: dict) -> str:
    """许可证签名：复合表达式按规范化文本比较，单许可证按规范化标识比较。"""
    if entry.get("family") == "expression":
        return "expr:" + " ".join((entry.get("license_raw") or "").split())
    return "id:" + (entry.get("license") or "NOASSERTION")


def _is_conflict(entry: Optional[dict]) -> bool:
    return entry is not None and entry.get("verdict") in CONFLICT_VERDICTS


def _pkg_ref(entry: dict, distribution: Optional[str]) -> dict:
    """新增 / 移除列表中的包摘要行。"""
    return {
        "id": entry["id"],
        "name": entry["name"],
        "version": entry["version"],
        "license_raw": entry.get("license_raw", ""),
        "license": entry.get("license", ""),
        "family": entry.get("family", ""),
        "verdict": entry.get("verdict"),
        "base_verdict": entry.get("base_verdict"),
        "rule": entry.get("rule", ""),
        "depth": entry.get("depth"),
        "direct": entry.get("direct", False),
        "distribution": distribution,
    }


def _conflict_entry(
    entry: dict,
    distribution: Optional[str],
    change_type: str,
    baseline_verdict: Optional[str],
) -> dict:
    """新增冲突：当前制品、触发规则、最短路径与升级来源。"""
    ref = _pkg_ref(entry, distribution)
    ref.update(
        {
            "severity": entry.get("severity", ""),
            "rule_kind": entry.get("rule_kind", ""),
            "message": entry.get("message", ""),
            "shortest_path": list(entry.get("shortest_path", [])),
            "change_type": change_type,  # added / license_changed / verdict_changed
            "baseline_verdict": baseline_verdict,
        }
    )
    return ref


def _resolved_entry(
    base_entry: dict, cur_entry: Optional[dict], distribution: Optional[str]
) -> dict:
    """已解决冲突：基线中的冲突在当前版本消失的原因。"""
    ref = _pkg_ref(base_entry, distribution)
    ref.update(
        {
            "baseline_verdict": base_entry.get("verdict"),
            "baseline_rule": base_entry.get("rule", ""),
            "current_verdict": cur_entry.get("verdict") if cur_entry else None,
            "current_rule": cur_entry.get("rule", "") if cur_entry else "",
            # removed：包被移除；allow：变为兼容；exception：已确认例外
            "reason": "removed" if cur_entry is None else cur_entry.get("verdict"),
        }
    )
    return ref


def _diff_package_sets(
    base_pkgs: Dict[str, dict],
    cur_pkgs: Dict[str, dict],
    distribution: Optional[str] = None,
) -> dict:
    """对比两组按 id 索引的包结论（单制品整包，或多制品的单个制品）。"""
    base_ids = set(base_pkgs)
    cur_ids = set(cur_pkgs)

    added = [_pkg_ref(cur_pkgs[i], distribution) for i in sorted(cur_ids - base_ids)]
    removed = [_pkg_ref(base_pkgs[i], distribution) for i in sorted(base_ids - cur_ids)]
    license_changed: List[dict] = []
    verdict_changed: List[dict] = []
    new_conflicts: List[dict] = []
    resolved_conflicts: List[dict] = []
    unchanged = 0

    for pid in sorted(base_ids & cur_ids):
        b, c = base_pkgs[pid], cur_pkgs[pid]
        lic_diff = _license_signature(b) != _license_signature(c)
        verdict_diff = b.get("verdict") != c.get("verdict")

        if lic_diff:
            license_changed.append(
                {
                    "id": pid,
                    "name": c["name"],
                    "version": c["version"],
                    "baseline_license": b.get("license_raw", ""),
                    "current_license": c.get("license_raw", ""),
                    "baseline_license_canonical": b.get("license", ""),
                    "current_license_canonical": c.get("license", ""),
                    "baseline_verdict": b.get("verdict"),
                    "current_verdict": c.get("verdict"),
                    "baseline_rule": b.get("rule", ""),
                    "current_rule": c.get("rule", ""),
                    "distribution": distribution,
                }
            )
        if verdict_diff:
            verdict_changed.append(
                {
                    "id": pid,
                    "name": c["name"],
                    "version": c["version"],
                    "license_raw": c.get("license_raw", ""),
                    "license": c.get("license", ""),
                    "baseline_verdict": b.get("verdict"),
                    "current_verdict": c.get("verdict"),
                    "baseline_base_verdict": b.get("base_verdict"),
                    "current_base_verdict": c.get("base_verdict"),
                    "baseline_rule": b.get("rule", ""),
                    "current_rule": c.get("rule", ""),
                    "distribution": distribution,
                }
            )
        if not lic_diff and not verdict_diff:
            unchanged += 1

        if _is_conflict(c) and not _is_conflict(b):
            change_type = "license_changed" if lic_diff else "verdict_changed"
            new_conflicts.append(
                _conflict_entry(c, distribution, change_type, b.get("verdict"))
            )
        elif _is_conflict(b) and not _is_conflict(c):
            resolved_conflicts.append(_resolved_entry(b, c, distribution))

    # 新增包中的冲突 / 随包移除而消失的冲突
    for pid in sorted(cur_ids - base_ids):
        c = cur_pkgs[pid]
        if _is_conflict(c):
            new_conflicts.append(_conflict_entry(c, distribution, "added", None))
    for pid in sorted(base_ids - cur_ids):
        b = base_pkgs[pid]
        if _is_conflict(b):
            resolved_conflicts.append(_resolved_entry(b, None, distribution))

    new_conflicts.sort(key=lambda x: (_VERDICT_ORDER.get(x["verdict"], 9), x["id"]))
    resolved_conflicts.sort(key=lambda x: x["id"])

    return {
        "summary": {
            "total_baseline": len(base_pkgs),
            "total_current": len(cur_pkgs),
            "added": len(added),
            "removed": len(removed),
            "license_changed": len(license_changed),
            "verdict_changed": len(verdict_changed),
            "unchanged": unchanged,
            "new_conflicts": len(new_conflicts),
            "resolved_conflicts": len(resolved_conflicts),
        },
        "added": added,
        "removed": removed,
        "license_changed": license_changed,
        "verdict_changed": verdict_changed,
        "new_conflicts": new_conflicts,
        "resolved_conflicts": resolved_conflicts,
    }


def compare_results(baseline: dict, current: dict) -> dict:
    """对比两个 :func:`analyzer.analyze` 结果，返回对比报告（不含项目元信息）。

    单制品结果返回 ``mode == "single"`` 的平铺报告；
    多制品结果返回 ``mode == "multi"``，``distributions`` 为按制品分别对比的明细，
    顶层 ``new_conflicts`` / ``resolved_conflicts`` 为跨制品汇总（均带制品名）。
    """
    base_mode = baseline.get("mode", "single")
    cur_mode = current.get("mode", "single")
    if base_mode != cur_mode:
        raise DiffError(
            f"两个项目的审查模式不同（基线 {base_mode} / 当前 {cur_mode}），无法对比；"
            "请选择两个同为单制品或同为多制品的项目"
        )
    if cur_mode == "multi":
        return _compare_multi(baseline, current)
    diff = _diff_package_sets(
        {p["id"]: p for p in baseline.get("packages", [])},
        {p["id"]: p for p in current.get("packages", [])},
        distribution=None,
    )
    return {"mode": "single", **diff}


def _compare_multi(baseline: dict, current: dict) -> dict:
    """多制品对比：按制品名对齐，逐制品比较各自的可达包集合。"""
    base_dists = {d["name"]: d for d in baseline.get("distributions", [])}
    cur_dists = {d["name"]: d for d in current.get("distributions", [])}

    dists_added = [
        {"name": n, "project_license": cur_dists[n].get("project_license", "")}
        for n in cur_dists
        if n not in base_dists
    ]
    dists_removed = [
        {"name": n, "project_license": base_dists[n].get("project_license", "")}
        for n in base_dists
        if n not in cur_dists
    ]

    compared: List[dict] = []
    all_new: List[dict] = []
    all_resolved: List[dict] = []
    totals: Dict[str, int] = {}

    for name in cur_dists:  # 按当前清单的制品顺序输出
        if name not in base_dists:
            continue
        b, c = base_dists[name], cur_dists[name]
        diff = _diff_package_sets(
            {p["id"]: p for p in b.get("packages", [])},
            {p["id"]: p for p in c.get("packages", [])},
            distribution=name,
        )
        compared.append(
            {
                "name": name,
                "baseline_license": b.get("project_license", ""),
                "current_license": c.get("project_license", ""),
                **diff,
            }
        )
        all_new.extend(diff["new_conflicts"])
        all_resolved.extend(diff["resolved_conflicts"])
        for key, value in diff["summary"].items():
            totals[key] = totals.get(key, 0) + value

    all_new.sort(
        key=lambda x: (
            _VERDICT_ORDER.get(x["verdict"], 9),
            x["distribution"] or "",
            x["id"],
        )
    )
    all_resolved.sort(key=lambda x: (x["distribution"] or "", x["id"]))
    # 汇总计数按"制品 × 包"计次（同一共享包出现在多个制品中会分别计数）
    totals["distributions_added"] = len(dists_added)
    totals["distributions_removed"] = len(dists_removed)
    totals["distributions_compared"] = len(compared)

    return {
        "mode": "multi",
        "summary": totals,
        "distributions_added": dists_added,
        "distributions_removed": dists_removed,
        "distributions": compared,
        "new_conflicts": all_new,
        "resolved_conflicts": all_resolved,
    }
