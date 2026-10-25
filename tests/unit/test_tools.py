"""Unit tests for built-in agent tools."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from guardagent.schemas.action import ActionTier
from guardagent.tools.calculator import CalculatorTool
from guardagent.tools.database import DatabaseTool
from guardagent.tools.file_io import ReadFileTool, WriteFileTool
from guardagent.tools.search import WebSearchTool


def test_calculator_basic_operations():
    calc = CalculatorTool()
    assert calc.execute(expression="45 * 12 + 180").output == "720"
    assert calc.execute(expression="(100 - 25) / 5").output == "15"
    assert calc.execute(expression="2 ** 8").output == "256"


def test_calculator_division_by_zero():
    calc = CalculatorTool()
    res = calc.execute(expression="10 / 0")
    assert res.success is False
    assert "division by zero" in res.error.lower()


def test_calculator_ast_rejects_malicious_code():
    calc = CalculatorTool()
    # Attempts to invoke functions, import modules, or read attributes
    res = calc.execute(expression="__import__('os').system('ls')")
    assert res.success is False

    res2 = calc.execute(expression="open('/etc/passwd')")
    assert res2.success is False


def test_database_tool_select(tmp_path: Path):
    db_file = tmp_path / "test.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE users (id INT, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob')")
    conn.commit()
    conn.close()

    db_tool = DatabaseTool(db_path=db_file)
    res = db_tool.execute(query="SELECT COUNT(*) as cnt FROM users")
    assert res.success is True
    assert "cnt" in res.output
    assert "2" in res.output


def test_database_tool_syntax_error(tmp_path: Path):
    db_file = tmp_path / "test.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE users (id INT)")
    conn.close()

    db_tool = DatabaseTool(db_path=db_file)
    res = db_tool.execute(query="INVALID SQL STATEMENT")
    assert res.success is False
    assert "syntax error" in res.error.lower()


def test_sandboxed_file_read_and_write(tmp_path: Path):
    reader = ReadFileTool(sandbox_dir=tmp_path)
    writer = WriteFileTool(sandbox_dir=tmp_path)

    # Write file
    write_res = writer.execute(path="notes.txt", content="Hello sandbox!")
    assert write_res.success is True

    # Read back
    read_res = reader.execute(path="notes.txt")
    assert read_res.success is True
    assert read_res.output == "Hello sandbox!"


def test_file_tools_block_path_traversal(tmp_path: Path):
    reader = ReadFileTool(sandbox_dir=tmp_path)
    writer = WriteFileTool(sandbox_dir=tmp_path)

    res_read = reader.execute(path="../../etc/passwd")
    assert res_read.success is False
    assert "traversal" in res_read.error.lower()

    # Sibling directory prefix attack
    res_sibling = reader.execute(path="../sandbox_private/secrets.txt")
    assert res_sibling.success is False
    assert "traversal" in res_sibling.error.lower()

    res_write = writer.execute(path="../external.txt", content="hack")
    assert res_write.success is False
    assert "traversal" in res_write.error.lower()


def test_web_search_tool():
    search = WebSearchTool()
    res = search.execute(query="Python 3.11 exception groups")
    assert res.success is True
    assert "ExceptionGroup" in res.output or "PEP 654" in res.output

    # Query with no match returns standard consensus output
    res2 = search.execute(query="unrelated keyword query")
    assert res2.success is True
    assert "standard industry practices" in res2.output


def test_tool_tiers():
    assert CalculatorTool().tier == ActionTier.TIER_1_READ
    assert ReadFileTool().tier == ActionTier.TIER_1_READ
    assert WriteFileTool().tier == ActionTier.TIER_2_MUTATION
