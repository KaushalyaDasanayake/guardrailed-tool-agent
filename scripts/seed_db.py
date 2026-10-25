"""Seed script to initialize local SQLite company database for testing and demonstration."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def seed_database(db_path: str | Path = "data/company.db") -> Path:
    target = Path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(target)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS employees")
    cur.execute(
        """
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            title TEXT NOT NULL,
            salary REAL NOT NULL,
            hire_date TEXT NOT NULL
        )
        """
    )

    employees = [
        ("Alice Vance", "Engineering", "Lead Architect", 145000.0, "2021-03-15"),
        ("Bob Chen", "Engineering", "Software Engineer", 105000.0, "2022-07-01"),
        ("Charlie Kim", "Marketing", "Marketing Manager", 95000.0, "2020-11-10"),
        ("Diana Prince", "Marketing", "Content Strategist", 82000.0, "2023-01-20"),
        ("Evan Wright", "Design", "Product Designer", 98000.0, "2022-05-12"),
    ]
    cur.executemany(
        "INSERT INTO employees (name, department, title, salary, hire_date) VALUES (?, ?, ?, ?, ?)",
        employees,
    )
    conn.commit()
    conn.close()
    return target


if __name__ == "__main__":
    path = seed_database()
    print(f"Database seeded at: {path}")
