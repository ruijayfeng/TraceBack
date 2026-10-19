"""Freeze arithmetic and all production dependencies before validation labels."""
from . import ROOT, OUT
from evaluation.framework.scoring_calibration.snapshot import read, save, sha, digest_map


def verify():
    for name in ('validation_formula_seal.json', 'validation_parameter_seal.json'):
        seal = read(OUT / name)
        for path, expected in seal['source_hashes'].items():
            if sha(path) != expected:
                raise ValueError('sealed_source_changed:' + path)
    return True


def run():
    if OUT.exists():
        raise ValueError('single_use_output_exists')
    old = ROOT / 'outputs/v5_scoring_calibration'
    previous = read(old / 'prediction_seal.json')
    for path, expected in previous['implementation'].items():
        if sha(ROOT / path) != expected:
            raise ValueError('development_implementation_changed:' + path)
    protected = read(old / 'baseline/seal.json')['protected_files']
    for path, expected in protected.items():
        if sha(path) != expected:
            raise ValueError('historical_baseline_changed:' + path)
    protected = dict(protected)
    for path in (ROOT / 'evaluation/framework/scoring_calibration').glob('*.py'):
        protected[str(path)] = sha(path)
    policy_path = ROOT / 'evaluation/configs/scoring_calibration.yaml'
    protected[str(policy_path)] = sha(policy_path)
    for name in ('prediction_seal.json', 'result.json', 'experiment_specification.json'):
        protected[str(old / name)] = sha(old / name)
    prepared = read(ROOT / 'outputs/v5_source_bound_observability_final/preparation.json')
    import yaml
    policy = yaml.safe_load(policy_path.read_text(encoding='utf8'))
    # New dataset namespaces are declared here before data generation or labels.
    sources = prepared['sources']
    renamed = {}
    for name, settings in sources.items():
        settings = dict(settings)
        settings['source_namespace'] = name.replace('traceback.lab.', 'validation.independent.')
        settings['network_namespace'] = 'validation.independent.network'
        settings['asset_namespace'] = 'validation.independent.assets'
        if settings.get('account_realm'):
            settings['account_realm'] = 'VALIDATION.INDEPENDENT'
        renamed[settings['source_namespace']] = settings
    config = dict(algorithm=prepared['algorithm'], sources=renamed)
    implementation = {str(p): sha(p) for p in (ROOT / 'backend/app').rglob('*.py')}
    implementation[str(ROOT / 'evaluation/framework/scoring_calibration/model.py')] = sha(ROOT / 'evaluation/framework/scoring_calibration/model.py')
    common = dict(status='SEALED_BEFORE_VALIDATION_LABELS', implementation_hash=digest_map(implementation),
        config_hash=digest_map(config), formula_hash=sha(ROOT / 'evaluation/framework/scoring_calibration/model.py'),
        parameter_hash=digest_map(policy), source_hashes=protected, threshold=.65,
        scoring_formula='C_STRONG_ANCHOR_CONTEXT_V1_RESEARCH', config=config, parameters=policy,
        local_sensitivity={k:[.9,1.1] for k in ('anchor_reliability','minimum_anchor_strength','parent_only_factor','time_floor','anchor_rarity_floor')},
        thresholds=[.60,.62,.64,.65,.66,.68,.70], labels_read=False,
        constraints='No refitting, no threshold selection, no new rules; all sensitivity predictions sealed before evaluation.')
    save(OUT / 'validation_formula_seal.json', common)
    save(OUT / 'validation_parameter_seal.json', common)
    print('FORMULA_AND_PARAMETERS_SEALED', len(protected), flush=True)


if __name__ == '__main__':
    run()
