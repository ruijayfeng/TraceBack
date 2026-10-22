"""Single fail-closed contract for evaluation annotations at alert ingress.

No values are interpreted as labels. Exact field names identify annotations;
vendor rule/product/UI labels remain ordinary observed security metadata.
"""
import re

GROUND_TRUTH_FORBIDDEN_FIELDS = frozenset({
    'ground_truth', 'groundtruth', 'ground_truth_path', 'label', 'labels',
    'attack_label', 'attack_flag', 'is_attack', 'malicious', 'is_malicious', 'gt', 'truth',
    'expected_stage', 'expected_chain', 'expected_behavior', 'expected_incident',
    'evaluation_label', 'gold_node', 'gold_edge', 'gold_chain', 'time_label', 'event_label',
    'attack_timeline', 'attack_description', 'known_malicious_ip',
    'stage_id', 'attack_stage', 'expected_community', 'attack_path',
})


def reject_truth(raw):
    def visit(value, parent=None):
        if type(value) is dict:
            for key, child in value.items():
                name = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', key).casefold().replace('-', '_').replace(' ', '_')
                vendor_label = name in {'label', 'labels'} and parent in {'rule', 'product', 'ui'}
                if name in GROUND_TRUTH_FORBIDDEN_FIELDS and not vendor_label:
                    raise ValueError('annotation_contamination')
                visit(child, name)
        elif type(value) is list:
            for child in value:
                visit(child, parent)
    visit(raw)
