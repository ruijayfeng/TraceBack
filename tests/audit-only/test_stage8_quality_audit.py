"""Audit calculations only. No production fixtures, policy or algorithms change."""
from pathlib import Path
from types import SimpleNamespace as NS
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from audit_stage8_relation_quality import alternate_path, components, graph_statistics, quantile, claim_key


def edge(a,b):
    return NS(stage_a_id=a,stage_b_id=b,relation_type='UNDIRECTED_EDGE')


def test_complete_four_node_clique_density_and_degrees():
    from itertools import combinations
    pairs=set(combinations('abcd',2))
    result=graph_statistics(list('abcd'),[edge(*p) for p in pairs])
    assert result['RELATION_EDGE_COUNT']==6 and result['GRAPH_DENSITY']==1
    assert result['AVERAGE_DEGREE']==result['MEDIAN_DEGREE']==result['P90_DEGREE']==3
    assert result['CONNECTED_COMPONENT_COUNT']==1 and result['LARGEST_COMPONENT_SIZE']==4
    assert all(alternate_path(pairs,p) for p in pairs)


def test_isolated_nodes_are_counted_in_density_and_degree_distribution():
    result=graph_statistics(list('abcd'),[edge('a','b')])
    assert result['ISOLATED_STAGE_COUNT']==2 and result['CONNECTED_COMPONENT_COUNT']==3
    assert result['MEDIAN_DEGREE']==.5 and result['AVERAGE_DEGREE']==.5
    assert result['GRAPH_DENSITY']==1/6


def test_edge_individually_redundant_does_not_imply_safe_bulk_removal():
    triangle={('a','b'),('b','c'),('a','c')}
    assert all(alternate_path(triangle,p) for p in triangle)
    assert len(components('abc',set())[0])==3
    assert not alternate_path({('a','b'),('b','c')},('a','b'))


def test_percentile_is_linear_interpolation():
    assert quantile([0,10],.9)==9
    assert quantile([], .9)==0
    assert quantile([7], .9)==7


def test_claim_grouping_ignores_alert_pairs_but_preserves_semantic_roles():
    args=dict(stage_a_id='a',stage_b_id='b',evidence_type='SAME_PROCESS_INSTANCE',direction_claim='UNDIRECTED',
        metadata=dict(identity={'process':'p'},role_a='process',role_b='process'))
    first=NS(**args,alert_a_id='x',alert_b_id='y')
    second=NS(**args,alert_a_id='u',alert_b_id='v')
    assert claim_key(first)==claim_key(second)
    second.metadata=dict(second.metadata,role_b='parent_process')
    assert claim_key(first)!=claim_key(second)
