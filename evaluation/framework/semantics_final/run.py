"""Reproducible staged entry point. Never advances to a new dataset."""
import sys
from . import ROOT
sys.path.insert(0,str(ROOT/'backend'))
if __name__=='__main__':
    stage=sys.argv[1]
    if stage in {'prepare','audit','freeze','blind','history_end'}:
        from . import runtime
        getattr(runtime,stage)()
    elif stage=='evaluate':
        from .evaluate import run
        run()
    elif stage=='downstream':
        from .downstream import run
        run()
    elif stage=='regression':
        from .regression import run
        run()
    elif stage=='finish':
        from .report import run
        run()
    else: raise ValueError(stage)
