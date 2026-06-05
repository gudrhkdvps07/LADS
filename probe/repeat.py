from __future__ import annotations

from typing import Any

RECHECK_REPEAT_TOTAL = 3        # 재현 검증 총 반복 횟수
LENGTH_SIGNAL_THRESHOLD = 0.05  # 길이 기준값
TIME_SIGNAL_THRESHOLD = 4.5     # 시간 기준값

# SQLi 단건 강한 신호로 볼 DB 에러 키워드 목록
DB_ERROR_KEYWORDS = (
    "you have an error in your sql syntax",
    "check the manual that corresponds to your mysql server version",
    "check the manual that fits your mysql server version",
    "warning: mysql",
    "warning: mysqli",
    "mysqlsyntaxerrorexception",
    "supplied argument is not a valid mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mysqli_",
    "pdoexception",
    "sqlstate",
    "unknown column",
    "duplicate entry",
    "division by zero",
    "column count doesn't match",
    "the used select statements have a different number",
)


# 결과의 SQLi 분류 반환
def _sqli_category(item: dict) -> str | None:
    meta = item.get("meta") or {}
    category = meta.get("category")
    if category:
        return str(category)
    vuln_type = str(meta.get("vuln_type") or "").lower()
    if "sqli" in vuln_type or "sql" in vuln_type:
        return "error"
    return None


# 결과의 비교 역할 반환
def _result_role(item: dict) -> str:
    return str((item.get("meta") or {}).get("role") or "attack")


# 응답 본문에 DB 에러가 있는지 반환
def _has_db_error(item: dict) -> bool:
    body = str(item.get("response_body") or "").lower()
    return any(sig in body for sig in DB_ERROR_KEYWORDS)


# 응답 길이 차이 비율 반환
def _length_diff(left: dict, right: dict) -> float:
    left_len = int(left.get("length") or 0)
    right_len = int(right.get("length") or 0)
    return abs(left_len - right_len) / max(left_len, right_len, 1)


# 재현 묶음 키를 반환
def _reproduction_key(item: dict) -> str:
    meta = item.get("meta") or {}
    return ":".join(
        str(part or "")
        for part in (
            item.get("task_group_id"),
            meta.get("role"),
            meta.get("family"),
            item.get("payload"),
        )
    )


# 재현 대상 결과에 반복 메타 설정
def _mark_initial_recheck_result(item: dict) -> None:
    item["repeat_index"] = 1
    item["repeat_total"] = RECHECK_REPEAT_TOTAL
    item["reproduction_key"] = _reproduction_key(item)


# 재현 요청 task를 생성해 반환
def _clone_recheck_task(task: dict, source_result: dict, repeat_index: int) -> dict:
    cloned = dict(task)
    cloned["id"] = f"{task.get('id')}_rep{repeat_index}"
    cloned["repeat_index"] = repeat_index
    cloned["repeat_total"] = RECHECK_REPEAT_TOTAL
    cloned["reproduction_key"] = source_result.get("reproduction_key") or _reproduction_key(source_result)
    return cloned


# SQLi 재현이 필요한 결과 ID 목록을 반환
def _select_recheck_result_ids(results: list[dict]) -> set[str]:
    groups: dict[str, list[dict]] = {}
    for item in results:
        category = _sqli_category(item)
        group_id = item.get("task_group_id")
        if not category or not group_id:
            continue
        groups.setdefault(str(group_id), []).append(item)

    selected: set[str] = set()

    for group in groups.values():
        if any(_has_db_error(item) for item in group):
            continue

        category = _sqli_category(group[0])
        by_role: dict[str, list[dict]] = {}
        for item in group:
            by_role.setdefault(_result_role(item), []).append(item)

        if category == "boolean":  # true/false 응답 길이 차이가 있으면 재현 검증 대상으로 선택
            true_items = by_role.get("true_attack") or []
            false_items = by_role.get("false_attack") or []
            if true_items and false_items and _length_diff(true_items[0], false_items[0]) >= LENGTH_SIGNAL_THRESHOLD:
                selected.update(str(item.get("id")) for item in true_items + false_items if item.get("id"))

        elif category == "time":  # delay 응답이 기준 시간 이상이면 baseline과 함께 재현 검증 대상으로 선택
            delay_items = by_role.get("delay_attack") or []
            baseline_items = by_role.get("time_baseline") or []
            if any(float(item.get("elapsed") or 0.0) >= TIME_SIGNAL_THRESHOLD for item in delay_items):
                selected.update(str(item.get("id")) for item in delay_items + baseline_items if item.get("id"))

        elif category == "order_by":  # valid/invalid ORDER BY 응답 차이가 있으면 두 역할 모두 재현 검증 대상으로 선택
            valid_items = by_role.get("valid_order") or []
            invalid_items = by_role.get("invalid_order") or []
            if valid_items and invalid_items:
                status_changed = valid_items[0].get("status") != invalid_items[0].get("status")
                length_changed = _length_diff(valid_items[0], invalid_items[0]) >= LENGTH_SIGNAL_THRESHOLD
                if status_changed or length_changed:
                    selected.update(str(item.get("id")) for item in valid_items + invalid_items if item.get("id"))

        elif category == "error":  # DB 에러 없이 status/length 차이만 있으면 attack 요청만 재현 검증 대상으로 선택
            original = (by_role.get("original") or [None])[0]
            safe = (by_role.get("safe") or [None])[0]
            attack_items = by_role.get("attack") or []
            for attack in attack_items:
                status_changed = bool(original and original.get("status") != attack.get("status"))
                safe_changed = bool(safe and safe.get("status") != attack.get("status"))
                length_changed = bool(original and _length_diff(original, attack) >= LENGTH_SIGNAL_THRESHOLD)
                if status_changed or safe_changed or length_changed:
                    selected.add(str(attack.get("id")))

    return selected


# 재현 요청 task 목록을 생성하여 반환
def build_recheck_tasks(tasks: list[dict], results: list[dict]) -> list[dict]:
    selected_ids = _select_recheck_result_ids(results)
    if not selected_ids:
        return []

    task_by_id = {str(task.get("id")): task for task in tasks if task.get("id")}
    result_by_id = {str(item.get("id")): item for item in results if item.get("id")}
    recheck_tasks: list[dict] = []

    for result_id in sorted(selected_ids):
        task = task_by_id.get(result_id)
        result = result_by_id.get(result_id)
        if not task or not result:
            continue
        _mark_initial_recheck_result(result)
        for repeat_index in range(2, RECHECK_REPEAT_TOTAL + 1):
            recheck_tasks.append(_clone_recheck_task(task, result, repeat_index))

    return recheck_tasks
