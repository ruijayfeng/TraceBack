"""Read-only representative membership projection; never count dedupe wrappers twice."""


def representative_member_count(incident, owner):
    return len({owner.get(a, a) for a in incident.alert_ids})


def expanded_member_count(incident):
    return len(incident.alert_ids)


def incident_metrics(incidents, groups):
    owner = {a: g.representative_alert_id for g in groups for a in g.alert_ids}
    counts = dict(representative_singleton_incident_count=0,
                  correlated_multi_alert_incident_count=0, incidents_with_dedupe_expansion_count=0)
    for incident in incidents:
        n = representative_member_count(incident, owner)
        counts['representative_singleton_incident_count' if n == 1 else
               'correlated_multi_alert_incident_count'] += 1
        counts['incidents_with_dedupe_expansion_count'] += expanded_member_count(incident) > n
    return counts


# SQL counterpart uses formal DedupeGroup membership. Bind dedupe_groups,
# incidents, incidents, attack_chains; no inference from aggregate deltas.
MEMBERSHIP_SQL = """WITH owners AS (
 SELECT unnest(CAST(json_extract(payload, '$.alert_ids') AS VARCHAR[])) AS aid,
 json_extract_string(payload, '$.representative_alert_id') AS representative
 FROM read_parquet(?)), members AS (
 SELECT object_id, unnest(CAST(json_extract(payload, '$.alert_ids') AS VARCHAR[])) AS aid
 FROM read_parquet(?)), membership AS (
 SELECT object_id, count(*) AS expanded_member_count,
 count(DISTINCT coalesce(representative, members.aid)) AS representative_member_count
 FROM members LEFT JOIN owners ON members.aid = owners.aid GROUP BY object_id), base AS (
 SELECT i.object_id, i.payload, i.event_time, m.expanded_member_count AS alert_count,
 m.expanded_member_count, m.representative_member_count,
 json_array_length(c.payload, '$.nodes') AS node_count,
 json_array_length(c.payload, '$.edges') AS edge_count
 FROM read_parquet(?) i JOIN membership m USING(object_id)
 LEFT JOIN read_parquet(?) c ON i.object_id = json_extract_string(c.payload, '$.incident_id')) """


def membership_paths(q, store):
    return [q.table(store, k) for k in ('dedupe_groups', 'incidents', 'incidents', 'attack_chains')]
