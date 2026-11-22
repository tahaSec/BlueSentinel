"""Correlate time-adjacent alerts by shared account, host, IP, or process."""

from datetime import timedelta
import math
from typing import List, Set

from backend.models.correlation_group import CorrelationGroup
from backend.models.detection_alert import DetectionAlert


def _keys(alert: DetectionAlert) -> Set[str]:
    keys = set(alert.correlation_keys)
    if alert.username and alert.username.strip() and not any(
        key.startswith("username:") for key in keys
    ):
        keys.add("username:" + alert.username.casefold())
    return keys


def correlate_alerts(
    alerts: List[DetectionAlert], window_seconds: float = 900
) -> List[CorrelationGroup]:
    """Group two or more alerts that share an entity within a time window.

    Correlation is explainable: every group lists the shared, namespaced keys
    (username, source IP, host, or process). Missing usernames are not treated
    as a common identity; other explicit keys may still support a group.
    """
    if (
        isinstance(window_seconds, bool)
        or not isinstance(window_seconds, (int, float))
        or not math.isfinite(window_seconds)
        or window_seconds <= 0
    ):
        raise ValueError("window_seconds must be a positive finite number")

    alerts = list(alerts)
    parent = list(range(len(alerts)))
    keys = [_keys(alert) for alert in alerts]
    shared_by_pair = {}

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left, right):
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    window = timedelta(seconds=window_seconds)
    for left in range(len(alerts)):
        for right in range(left + 1, len(alerts)):
            shared = keys[left].intersection(keys[right])
            if not shared:
                continue
            first, second = alerts[left], alerts[right]
            close_in_time = (
                first.first_seen <= second.last_seen + window
                and second.first_seen <= first.last_seen + window
            )
            if close_in_time:
                union(left, right)
                shared_by_pair[(left, right)] = shared

    components = {}
    for index in range(len(alerts)):
        components.setdefault(find(index), []).append(index)

    groups = []
    for indexes in components.values():
        if len(indexes) < 2:
            continue
        group_alerts = sorted(
            (alerts[index] for index in indexes),
            key=lambda item: (item.first_seen, item.rule_id, item.username or ""),
        )
        group_keys = set()
        for pair, values in shared_by_pair.items():
            if pair[0] in indexes and pair[1] in indexes:
                group_keys.update(values)
        usernames = [alert.username for alert in group_alerts if alert.username and alert.username.strip()]
        username_keys = {value.casefold() for value in usernames}
        username = usernames[0] if len(username_keys) == 1 and usernames else None
        techniques = sorted({
            technique for alert in group_alerts for technique in alert.attack_techniques
        })
        key_text = ", ".join(sorted(group_keys))
        groups.append(CorrelationGroup(
            username=username,
            alerts=group_alerts,
            first_seen=min(alert.first_seen for alert in group_alerts),
            last_seen=max(alert.last_seen for alert in group_alerts),
            attack_techniques=techniques,
            correlation_keys=sorted(group_keys),
            explanation="Alerts share {} within {} seconds.".format(key_text, window_seconds),
        ))

    groups.sort(key=lambda group: (group.first_seen, group.username or "", group.correlation_keys))
    return groups
