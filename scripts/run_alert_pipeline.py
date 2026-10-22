"""Official ①–④ CLI. Read-only input; stop before ⑤ Alert → Community."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'backend'))
from app.services.alert_pipeline import OFFICIAL_PIPELINE_ENTRY, load_alert_pipeline
from app.stages.behavior import semantic_input
from app.stages.config import load_stage_config


def execute(input_path):
    result = load_alert_pipeline(input_path)
    policy = load_stage_config(Path(__file__).resolve().parents[1]/'configs/behavior-stage-v1.yaml')
    fields = [(a, semantic_input(a, policy)[0]) for a in result.alerts]
    summary = dict(OFFICIAL_PIPELINE_ENTRY=OFFICIAL_PIPELINE_ENTRY,
        **result.noise_filter.statistics, CANONICAL_ALERTS=len(result.noise_filter.original_alerts),
        BEHAVIOR_INPUT=len(result.behaviors),
        BEHAVIOR_DISTRIBUTION=dict(Counter(b.behavior for b in result.behaviors)),
        EDR_PROCESS_NAME_AVAILABLE_TO_BEHAVIOR=sum(a.source_type.value=='edr' and 'process_name' in f for a,f in fields),
        EDR_EXECUTABLE_AVAILABLE_TO_BEHAVIOR=sum(a.source_type.value=='edr' and 'executable' in f for a,f in fields),
        HOST_EXECUTABLE_AVAILABLE_TO_BEHAVIOR=sum(a.raw_alert.get('source_type')=='host_audit' and 'executable' in f for a,f in fields),
        CURRENT_PIPELINE_STAGE='BEHAVIOR_NORMALIZATION_COMPLETE', NEXT_STAGE_STARTED=False)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    execute(parser.parse_args().input)
