"""CLI error handling: no tracebacks, correct exit codes."""
import argparse
from vulnpilot.cli import cmd_verify


def test_verify_missing_csv_clean_error(capsys):
    """verify on a nonexistent path must return 1 with a clean ERROR, no traceback."""
    args = argparse.Namespace(csv="/nonexistent/definitely_missing.csv",
                              kev=None, epss=None, no_colour=True,
                              evidence=None, evidence_out=None)
    rc = cmd_verify(args)
    captured = capsys.readouterr()
    assert rc == 1
    assert "ERROR" in captured.err
    assert "Traceback" not in captured.err + captured.out
