#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""访问密钥仓储。"""

from __future__ import annotations

from typing import Any

from ..utils.database import ConnectionFactory
from ..utils.local_time import now_local_datetime_text


class AccessKeyRepository:
    """负责数据面访问密钥的数据访问。"""

    MODEL_PERMISSIONS_ALL = "*"

    def __init__(self, get_connection: ConnectionFactory):
        self._get_connection = get_connection
        self._ensure_table()

    def _ensure_table(self) -> None:
        """初始化访问密钥表与索引。"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS access_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_value TEXT,
                    masked_key TEXT NOT NULL,
                    access_enabled INTEGER NOT NULL DEFAULT 1,
                    model_permissions TEXT NOT NULL DEFAULT '*',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            columns = {str(row["name"]).strip() for row in cursor.execute("PRAGMA table_info(access_keys)").fetchall()}
            if "key_value" not in columns:
                cursor.execute("ALTER TABLE access_keys ADD COLUMN key_value TEXT")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_keys_hash ON access_keys(key_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_keys_name ON access_keys(name)")

    def create(
        self,
        name: str,
        key_hash: str,
        key_value: str,
        masked_key: str,
        model_permissions: str = MODEL_PERMISSIONS_ALL,
    ) -> int:
        """创建访问密钥记录。"""
        now_text = now_local_datetime_text()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO access_keys (
                    name, key_hash, key_value, masked_key, access_enabled, model_permissions, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (name, key_hash, key_value, masked_key, model_permissions, now_text, now_text),
            )
            return int(cursor.lastrowid)

    def list_all(self) -> list[dict[str, Any]]:
        """查询全部访问密钥。"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, key_value, masked_key, access_enabled, model_permissions, created_at, updated_at
                FROM access_keys
                ORDER BY id DESC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_by_id(self, key_id: int) -> dict[str, Any] | None:
        """按 ID 查询访问密钥。"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, key_value, masked_key, access_enabled, model_permissions, created_at, updated_at
                FROM access_keys
                WHERE id = ?
                """,
                (key_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        """按密钥哈希查询访问密钥。"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, key_value, masked_key, access_enabled, model_permissions, created_at, updated_at
                FROM access_keys
                WHERE key_hash = ?
                """,
                (key_hash,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def update(
        self,
        key_id: int,
        *,
        name: str | None = None,
        access_enabled: bool | None = None,
        model_permissions: str | None = None,
    ) -> bool:
        """更新访问密钥元数据。"""
        updates: list[str] = []
        params: list[Any] = []
        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if access_enabled is not None:
            updates.append("access_enabled = ?")
            params.append(1 if access_enabled else 0)
        if model_permissions is not None:
            updates.append("model_permissions = ?")
            params.append(model_permissions)
        if not updates:
            return False

        updates.append("updated_at = ?")
        params.append(now_local_datetime_text())
        params.append(key_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                UPDATE access_keys
                SET {", ".join(updates)}
                WHERE id = ?
                """,
                params,
            )
            return cursor.rowcount > 0

    def update_secret(self, key_id: int, key_hash: str, key_value: str, masked_key: str) -> bool:
        """更新访问密钥的可复制明文与哈希。"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE access_keys
                SET key_hash = ?, key_value = ?, masked_key = ?, updated_at = ?
                WHERE id = ?
                """,
                (key_hash, key_value, masked_key, now_local_datetime_text(), key_id),
            )
            return cursor.rowcount > 0

    def delete(self, key_id: int) -> bool:
        """删除访问密钥。"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM access_keys WHERE id = ?", (key_id,))
            return cursor.rowcount > 0

    def count_enabled(self) -> int:
        """统计启用中的访问密钥数量。"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS count FROM access_keys WHERE access_enabled = 1")
            return int(cursor.fetchone()["count"])
