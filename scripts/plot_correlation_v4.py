"""Standalone scientific figures from frozen development receipts only."""
from pathlib import Path
import json
import sys
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'outputs/correlation_v4'
sys.path.insert(0, str(OUT/'plot_dependencies'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


def read(name): return json.loads((OUT/name).read_text(encoding='utf8'))


def run():
    destination = OUT/'figures'
    destination.mkdir(exist_ok=True)
    data = read('SCORE_DISTRIBUTION.json')
    bins = list(data['v4']['all']['histogram'])
    x = np.arange(len(bins))
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.8), layout='constrained')
    for ax, population in zip(axes, ('all', 'accepted', 'rejected')):
        for version, offset, color in [('v3', -.18, '#8b919b'), ('v4', .18, '#126b70')]:
            counts = data[version][population]['histogram']
            ax.bar(x+offset, [counts[b] for b in bins], width=.36, label=version, color=color)
        ax.set_xticks(x, [b.replace('[', '').replace(')', '') for b in bins], rotation=65, ha='right', fontsize=8)
        ax.set_yscale('symlog', linthresh=1)
        ax.set_ylabel('Candidate count (symlog scale)')
        ax.set_xlabel('Score interval')
        ax.set_title(population.capitalize()+' candidates')
        ax.grid(axis='y', alpha=.18)
        ax.legend(frameon=False)
    fig.suptitle('russellmitchell: v3 / v4 score distribution\nOne best valid complete member pair per candidate; best rejected pair if no valid pair', fontsize=12)
    fig.savefig(destination/'score_distribution.png', dpi=180)
    fig.savefig(destination/'score_distribution.svg')
    plt.close(fig)
    evidence = read('EDGE_EVIDENCE_ANALYSIS.json')
    fig, axes = plt.subplots(1, 2, figsize=(14, 7), layout='constrained')
    for ax, population in zip(axes, ('accepted', 'rejected')):
        families = sorted(set(evidence['v3']['evidence_composition'][population]) | set(evidence['v4']['evidence_composition'][population]))
        y = np.arange(len(families))
        for version, offset, color in [('v3', -.18, '#8b919b'), ('v4', .18, '#126b70')]:
            counts = evidence[version]['evidence_composition'][population]
            ax.barh(y+offset, [counts.get(f, 0) for f in families], height=.36, label=version, color=color)
        ax.set_yticks(y, [f.replace('_', ' ').replace(':', ' / ') for f in families], fontsize=8)
        ax.set_xscale('symlog', linthresh=1)
        ax.set_xlabel('Selected candidate fact count (symlog scale)')
        ax.set_title(population.capitalize()+' evidence composition')
        ax.grid(axis='x', alpha=.18)
        ax.legend(frameon=False)
    fig.suptitle('Observable evidence families, not attack correctness labels', fontsize=12)
    fig.savefig(destination/'evidence_composition.png', dpi=180)
    fig.savefig(destination/'evidence_composition.svg')
    plt.close(fig)
    print(json.dumps({'figures': [p.relative_to(ROOT).as_posix() for p in sorted(destination.iterdir())]}))


if __name__ == '__main__': run()
