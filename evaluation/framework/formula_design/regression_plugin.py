"""Reuse the accepted legacy write redirection at this experiment's destination."""
from . import OUT


def pytest_collection_modifyitems(items):
    from evaluation.framework.preformula_baseline import regression_plugin as accepted
    old=accepted.OUT
    try:
        accepted.OUT=OUT
        accepted.pytest_collection_modifyitems(items)
    finally:accepted.OUT=old
