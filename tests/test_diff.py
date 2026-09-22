"""版本对比（diff）测试：分析引擎层 + HTTP API 端到端。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["LICENSEGATE_DB"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402

from app import analyzer, diff, policies  # noqa: E402
from app import main  # noqa: E402

client = TestClient(main.app)

PERMISSIVE = policies.POLICIES["permissive"]

# ---------------------------------------------------------------------------
# 引擎层：compare_results
# ---------------------------------------------------------------------------

BASE_MANIFEST = {
    "project": {"name": "demo", "version": "1.0"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["web", "log", "legacy"]},
        {"name": "web", "version": "1", "license": "MIT", "dependencies": ["crypto"]},
        {"name": "log", "version": "1", "license": "BSD-3-Clause", "dependencies": []},
        {"name": "legacy", "version": "1", "license": "MIT", "dependencies": []},
        {"name": "crypto", "version": "1", "license": "Apache-2.0", "dependencies": []},
    ],
}

# 变化：log 改许可证（BSD→GPL-3.0，新增冲突）、legacy 移除、新增 ui（含 GPL 传递依赖）、
# crypto 版本升级（name@version 对齐 → 旧版本移除 + 新版本新增）
CUR_MANIFEST = {
    "project": {"name": "demo", "version": "2.0"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["web", "log", "ui"]},
        {"name": "web", "version": "1", "license": "MIT", "dependencies": ["crypto@2"]},
        {"name": "log", "version": "1", "license": "GPL-3.0", "dependencies": []},
        {"name": "ui", "version": "1", "license": "MIT", "dependencies": ["gpl-lib"]},
        {"name": "gpl-lib", "version": "1", "license": "GPL-3.0", "dependencies": []},
        {"name": "crypto", "version": "2", "license": "Apache-2.0", "dependencies": []},
    ],
}


def compare(base_manifest=BASE_MANIFEST, cur_manifest=CUR_MANIFEST,
            base_exceptions=None, cur_exceptions=None, policy=PERMISSIVE):
    base = analyzer.analyze(base_manifest, policy, exceptions=base_exceptions)
    cur = analyzer.analyze(cur_manifest, policy, exceptions=cur_exceptions)
    return diff.compare_results(base, cur)


def test_single_diff_summary_and_alignment():
    rep = compare()
    assert rep["mode"] == "single"
    s = rep["summary"]
    # crypto@1 → crypto@2 按 name@version 对齐：旧版本移除、新版本新增
    assert {p["id"] for p in rep["added"]} == {"ui@1", "gpl-lib@1", "crypto@2"}
    assert {p["id"] for p in rep["removed"]} == {"legacy@1", "crypto@1"}
    assert s["added"] == 3 and s["removed"] == 2
    assert s["unchanged"] == 2  # app@1、web@1 结论与许可证均未变
    assert s["total_baseline"] == 5 and s["total_current"] == 6


def test_single_diff_license_and_verdict_changes():
    rep = compare()
    lic = {c["id"]: c for c in rep["license_changed"]}
    assert set(lic) == {"log@1"}
    assert lic["log@1"]["baseline_license"] == "BSD-3-Clause"
    assert lic["log@1"]["current_license"] == "GPL-3.0"
    assert lic["log@1"]["baseline_verdict"] == "allow"
    assert lic["log@1"]["current_verdict"] == "deny"

    vc = {c["id"]: c for c in rep["verdict_changed"]}
    assert set(vc) == {"log@1"}
    assert vc["log@1"]["baseline_verdict"] == "allow"
    assert vc["log@1"]["current_verdict"] == "deny"


def test_single_diff_new_conflicts_carry_rule_and_path():
    rep = compare()
    assert rep["summary"]["new_conflicts"] == 2
    nc = {c["id"]: c for c in rep["new_conflicts"]}
    assert set(nc) == {"log@1", "gpl-lib@1"}

    # 新增依赖引入的冲突：当前制品（单制品为 None）、触发规则、最短路径
    gpl = nc["gpl-lib@1"]
    assert gpl["change_type"] == "added"
    assert gpl["distribution"] is None
    assert gpl["verdict"] == "deny"
    assert gpl["rule"].startswith("POLICY_DENY:")
    assert gpl["shortest_path"] == ["app@1", "ui@1", "gpl-lib@1"]
    assert gpl["depth"] == 2
    assert gpl["baseline_verdict"] is None

    # 许可证变化升级的冲突
    log = nc["log@1"]
    assert log["change_type"] == "license_changed"
    assert log["baseline_verdict"] == "allow"
    assert log["shortest_path"] == ["app@1", "log@1"]


def test_single_diff_resolved_conflicts():
    # 基线有 GPL 冲突，当前版本移除该包 → resolved（reason=removed）
    base = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ]
    }
    cur = {"packages": [
        {"name": "app", "version": "1", "license": "MIT", "dependencies": []},
    ]}
    rep = compare(base, cur)
    assert rep["summary"]["resolved_conflicts"] == 1
    r = rep["resolved_conflicts"][0]
    assert r["id"] == "g@1"
    assert r["reason"] == "removed"
    assert r["baseline_verdict"] == "deny"
    assert r["current_verdict"] is None


def test_exception_in_current_marks_conflict_resolved():
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ]
    }
    exc = {"g@1": {"note": "法务已批", "approved_at": "t"}}
    rep = compare(manifest, manifest, cur_exceptions=exc)
    assert rep["summary"]["new_conflicts"] == 0
    assert rep["summary"]["resolved_conflicts"] == 1
    r = rep["resolved_conflicts"][0]
    assert r["reason"] == "exception"
    assert r["current_verdict"] == "exception"


def test_exception_in_baseline_makes_new_conflict_when_missing():
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ]
    }
    exc = {"g@1": {"note": "旧审批", "approved_at": "t"}}
    rep = compare(manifest, manifest, base_exceptions=exc)
    assert rep["summary"]["new_conflicts"] == 1
    nc = rep["new_conflicts"][0]
    assert nc["id"] == "g@1"
    assert nc["change_type"] == "verdict_changed"
    assert nc["baseline_verdict"] == "exception"


def test_license_change_canonical_equivalent_not_reported():
    # 别名写法变化（mit → MIT）规范化后相同，不算许可证变化
    base = {"packages": [
        {"name": "app", "version": "1", "license": "mit", "dependencies": []},
    ]}
    cur = {"packages": [
        {"name": "app", "version": "1", "license": "MIT", "dependencies": []},
    ]}
    rep = compare(base, cur)
    assert rep["summary"]["license_changed"] == 0
    assert rep["summary"]["unchanged"] == 1


def test_mode_mismatch_raises():
    single = analyzer.analyze(BASE_MANIFEST, PERMISSIVE)
    multi = analyzer.analyze(
        {
            "packages": [
                {"name": "a", "version": "1", "license": "MIT", "dependencies": []},
            ],
            "distributions": [
                {"name": "d", "project_license": "MIT", "direct_dependencies": ["a"]},
            ],
        },
        PERMISSIVE,
    )
    import pytest

    with pytest.raises(diff.DiffError):
        diff.compare_results(single, multi)
    with pytest.raises(diff.DiffError):
        diff.compare_results(multi, single)


# ---------------------------------------------------------------------------
# 引擎层：多制品按制品分别对比
# ---------------------------------------------------------------------------

MULTI_BASE = {
    "project": {"name": "mono", "version": "1.0"},
    "packages": [
        {"name": "core", "version": "1", "license": "MIT", "dependencies": ["net"]},
        {"name": "climain", "version": "1", "license": "MIT", "dependencies": ["net"]},
        {"name": "net", "version": "1", "license": "LGPL-3.0", "dependencies": []},
        {"name": "extra", "version": "1", "license": "MIT", "dependencies": []},
    ],
    "distributions": [
        {"name": "sdk", "project_license": "MIT", "direct_dependencies": ["core"]},
        {"name": "cli", "project_license": "GPL-3.0", "direct_dependencies": ["climain"]},
    ],
}

# sdk 根改依赖 extra（新增制品内包）；net 许可证 LGPL→GPL-3.0；
# cli 制品移除，新增 service 制品
MULTI_CUR = {
    "project": {"name": "mono", "version": "2.0"},
    "packages": [
        {"name": "core", "version": "1", "license": "MIT",
         "dependencies": ["net", "extra"]},
        {"name": "net", "version": "1", "license": "GPL-3.0", "dependencies": []},
        {"name": "extra", "version": "1", "license": "MIT", "dependencies": []},
        {"name": "svc", "version": "1", "license": "MIT", "dependencies": ["net"]},
    ],
    "distributions": [
        {"name": "sdk", "project_license": "MIT", "direct_dependencies": ["core"]},
        {"name": "service", "project_license": "AGPL-3.0", "direct_dependencies": ["svc"]},
    ],
}


def compare_multi(base_exceptions=None, cur_exceptions=None):
    policy = policies.POLICIES["copyleft"]
    # copyleft 策略不允许 MIT 项目许可证 → 用宽松策略可覆盖的制品许可证重写
    base = dict(MULTI_BASE)
    cur = dict(MULTI_CUR)
    base["distributions"] = [
        {"name": "sdk", "project_license": "Apache-2.0", "direct_dependencies": ["core"]},
        {"name": "cli", "project_license": "Apache-2.0", "direct_dependencies": ["climain"]},
    ]
    cur["distributions"] = [
        {"name": "sdk", "project_license": "Apache-2.0", "direct_dependencies": ["core"]},
        {"name": "service", "project_license": "Apache-2.0", "direct_dependencies": ["svc"]},
    ]
    b = analyzer.analyze(base, PERMISSIVE, exceptions=base_exceptions)
    c = analyzer.analyze(cur, PERMISSIVE, exceptions=cur_exceptions)
    return diff.compare_results(b, c)


def test_multi_diff_per_distribution():
    rep = compare_multi()
    assert rep["mode"] == "multi"
    assert [d["name"] for d in rep["distributions_added"]] == ["service"]
    assert [d["name"] for d in rep["distributions_removed"]] == ["cli"]
    assert rep["summary"]["distributions_compared"] == 1

    # 只有 sdk 是共同制品：sdk 内 extra@1 新增、net@1 许可证变化
    sdk = rep["distributions"][0]
    assert sdk["name"] == "sdk"
    assert sdk["baseline_license"] == "Apache-2.0"
    assert {p["id"] for p in sdk["added"]} == {"extra@1"}
    assert {c["id"] for c in sdk["license_changed"]} == {"net@1"}
    assert sdk["summary"]["removed"] == 0

    # cli 的整个包集合不参与 sdk 的对比（按制品分别对比）
    assert all(p["distribution"] == "sdk" for p in sdk["added"])


def test_multi_diff_new_conflicts_carry_distribution():
    rep = compare_multi()
    # net@1 在 sdk 下：LGPL(预放行 allow) → GPL-3.0(deny)，新增冲突带制品名
    assert rep["summary"]["new_conflicts"] == 1
    nc = rep["new_conflicts"][0]
    assert nc["id"] == "net@1"
    assert nc["distribution"] == "sdk"
    assert nc["change_type"] == "license_changed"
    assert nc["verdict"] == "deny"
    assert nc["rule"].startswith("POLICY_DENY:")
    assert nc["shortest_path"] == ["core@1", "net@1"]
    # 制品内明细与汇总一致
    sdk = rep["distributions"][0]
    assert sdk["new_conflicts"][0]["id"] == "net@1"
    assert sdk["new_conflicts"][0]["distribution"] == "sdk"


def test_multi_diff_aggregated_summary_counts_per_distribution():
    # 共享包在多个制品中分别计数
    base = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "LGPL-3.0", "dependencies": []},
        ],
        "distributions": [
            {"name": "d1", "project_license": "MIT", "direct_dependencies": ["a"]},
            {"name": "d2", "project_license": "MIT", "direct_dependencies": ["b"]},
        ],
    }
    cur = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ],
        "distributions": base["distributions"],
    }
    b = analyzer.analyze(base, PERMISSIVE)
    c = analyzer.analyze(cur, PERMISSIVE)
    rep = diff.compare_results(b, c)
    assert rep["summary"]["new_conflicts"] == 2  # d1、d2 各一次
    assert {n["distribution"] for n in rep["new_conflicts"]} == {"d1", "d2"}
    assert len(rep["distributions"]) == 2


# ---------------------------------------------------------------------------
# API 层
# ---------------------------------------------------------------------------


def upload(manifest, policy="permissive"):
    res = client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(manifest).encode(), "application/json")},
        data={"policy_key": policy},
    )
    assert res.status_code == 200, res.text
    return res.json()["project_id"]


def post_diff(baseline_id, current_id, policy_key=None):
    body = {"baseline_id": baseline_id, "current_id": current_id}
    if policy_key:
        body["policy_key"] = policy_key
    return client.post("/api/diff", json=body)


def test_api_diff_single_projects():
    base_id = upload(BASE_MANIFEST)
    cur_id = upload(CUR_MANIFEST)
    res = post_diff(base_id, cur_id)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["report_format"] == "licensegate-diff/v1"
    assert data["mode"] == "single"
    assert data["baseline"]["id"] == base_id
    assert data["current"]["id"] == cur_id
    assert data["policy_mismatch"] is False
    assert data["summary"]["new_conflicts"] == 2
    nc = {c["id"]: c for c in data["new_conflicts"]}
    assert nc["gpl-lib@1"]["shortest_path"] == ["app@1", "ui@1", "gpl-lib@1"]
    assert nc["gpl-lib@1"]["distribution"] is None
    assert data["summary"]["resolved_conflicts"] == 0


def test_api_diff_multi_projects_per_distribution():
    base = dict(MULTI_BASE)
    base["distributions"] = [
        {"name": "sdk", "project_license": "Apache-2.0", "direct_dependencies": ["core"]},
        {"name": "cli", "project_license": "Apache-2.0", "direct_dependencies": ["climain"]},
    ]
    cur = dict(MULTI_CUR)
    cur["distributions"] = [
        {"name": "sdk", "project_license": "Apache-2.0", "direct_dependencies": ["core"]},
        {"name": "service", "project_license": "Apache-2.0", "direct_dependencies": ["svc"]},
    ]
    base_id = upload(base)
    cur_id = upload(cur)
    res = post_diff(base_id, cur_id)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["mode"] == "multi"
    assert [d["name"] for d in data["distributions_added"]] == ["service"]
    assert [d["name"] for d in data["distributions_removed"]] == ["cli"]
    sdk = data["distributions"][0]
    assert sdk["name"] == "sdk"
    assert {c["id"] for c in sdk["license_changed"]} == {"net@1"}
    nc = data["new_conflicts"][0]
    assert nc["distribution"] == "sdk"
    assert nc["shortest_path"] == ["core@1", "net@1"]


def test_api_diff_policy_mismatch_flag_and_override():
    base_id = upload(BASE_MANIFEST, policy="permissive")
    cur_id = upload(CUR_MANIFEST, policy="strict")

    res = post_diff(base_id, cur_id)
    assert res.status_code == 200
    assert res.json()["policy_mismatch"] is True
    assert res.json()["baseline"]["policy_key"] == "permissive"
    assert res.json()["current"]["policy_key"] == "strict"

    # 统一策略覆盖：两边都按 strict 重新计算
    res = post_diff(base_id, cur_id, policy_key="strict")
    assert res.status_code == 200
    data = res.json()
    assert data["policy_mismatch"] is False
    assert data["baseline"]["policy_key"] == "strict"
    assert data["current"]["policy_key"] == "strict"


def test_api_diff_respects_saved_exceptions():
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ]
    }
    base_id = upload(manifest)
    cur_id = upload(manifest)
    # 当前项目确认了例外 → 对比时该冲突记为已解决
    res = client.post(
        f"/api/projects/{cur_id}/exceptions/g@1", json={"note": "继续使用"}
    )
    assert res.status_code == 200
    data = post_diff(base_id, cur_id).json()
    assert data["summary"]["new_conflicts"] == 0
    assert data["summary"]["resolved_conflicts"] == 1
    assert data["resolved_conflicts"][0]["reason"] == "exception"


def test_api_diff_errors():
    pid = upload(BASE_MANIFEST)
    pid2 = upload(CUR_MANIFEST)
    # 同一项目
    assert post_diff(pid, pid).status_code == 400
    # 项目不存在
    assert post_diff(pid, 99999).status_code == 404
    assert post_diff(99999, pid).status_code == 404
    # 未知策略
    res = post_diff(pid, pid2, policy_key="nope")
    assert res.status_code == 400
    assert "未知策略" in res.json()["detail"]


def test_api_diff_mode_mismatch_rejected():
    single_id = upload(BASE_MANIFEST)
    multi = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": []},
        ],
        "distributions": [
            {"name": "d", "project_license": "MIT", "direct_dependencies": ["a"]},
        ],
    }
    multi_id = upload(multi)
    res = post_diff(single_id, multi_id)
    assert res.status_code == 400
    assert "模式不同" in res.json()["detail"]
    assert post_diff(multi_id, single_id).status_code == 400


def test_projects_list_exposes_mode():
    single_id = upload(BASE_MANIFEST)
    multi = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": []},
        ],
        "distributions": [
            {"name": "d", "project_license": "MIT", "direct_dependencies": ["a"]},
        ],
    }
    multi_id = upload(multi)
    projects = {p["id"]: p for p in client.get("/api/projects").json()["projects"]}
    assert projects[single_id]["mode"] == "single"
    assert projects[multi_id]["mode"] == "multi"
