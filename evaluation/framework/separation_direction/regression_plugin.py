"""Redirect legacy regression artifacts without weakening assertions."""
from . import OUT


def pytest_collection_modifyitems(items):
    from evaluation.framework.preformula_baseline import regression_plugin as accepted
    previous=accepted.OUT
    try:
        accepted.OUT=OUT
        accepted.pytest_collection_modifyitems(items)
    finally:accepted.OUT=previous
