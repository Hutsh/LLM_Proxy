import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.application.app_context import AppContext
from src.repositories import AccessKeyRepository, LogRepository
from src.services import AccessKeyService, LogService
from src.utils.database import create_connection_factory
from src.utils.local_time import now_local_datetime, now_local_datetime_text


class DummyLogger:
    def info(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def debug(self, *args, **kwargs):
        return None


class FakeConfigManager:
    def __init__(self, payload):
        self.payload = payload

    def get_raw_config(self):
        return deepcopy(self.payload)


class AccessKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self._db_path = Path(self._tempdir.name) / "requests.db"
        self._get_connection = create_connection_factory(self._db_path)
        self._config = {
            "providers": [
                {
                    "name": "demo",
                    "api": "https://example.com/v1/chat/completions",
                    "api_key": "sk-demo",
                    "model_list": ["gpt-4.1", "gpt-4.1-mini"],
                }
            ]
        }
        self._ctx = AppContext(
            logger=DummyLogger(),
            config_manager=cast(Any, FakeConfigManager(self._config)),
            root_path=Path(self._tempdir.name),
            flask_app=Flask(__name__),
        )
        self._repository = AccessKeyRepository(self._get_connection)
        self._service = AccessKeyService(self._ctx, self._repository)

    def tearDown(self) -> None:
        self._tempdir.cleanup()

    def test_create_access_key_generates_sk_token_and_lists_plaintext_for_copy(self) -> None:
        created = self._service.create_access_key("ci")
        listed = self._service.list_access_keys()

        self.assertTrue(created["api_key"].startswith("sk-"))
        self.assertEqual("ci", created["name"])
        self.assertEqual(1, len(listed))
        self.assertEqual(created["api_key"], listed[0]["api_key"])
        self.assertEqual(created["masked_key"], listed[0]["masked_key"])

    def test_create_access_key_accepts_custom_sk_token(self) -> None:
        created = self._service.create_access_key("custom", api_key="sk-local-test")
        resolved = self._service.get_access_key_by_token("sk-local-test")

        self.assertEqual("sk-local-test", created["api_key"])
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(created["id"], resolved["id"])

    def test_list_access_keys_backfills_legacy_plaintext_for_copy(self) -> None:
        now_text = now_local_datetime_text()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO access_keys (
                    name, key_hash, key_value, masked_key, access_enabled, model_permissions, created_at, updated_at
                )
                VALUES (?, ?, NULL, ?, 1, '*', ?, ?)
                """,
                (
                    "legacy",
                    self._service._hash_key("sk-legacy-secret"),
                    "sk-lega...cret",
                    now_text,
                    now_text,
                ),
            )

        listed = self._service.list_access_keys()
        copied_key = listed[0]["api_key"]
        resolved = self._service.get_access_key_by_token(copied_key)

        self.assertTrue(copied_key.startswith("sk-"))
        self.assertNotEqual("sk-lega...cret", copied_key)
        self.assertEqual(copied_key, listed[0]["api_key"])
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(listed[0]["id"], resolved["id"])

    def test_access_key_model_permissions_are_enforced(self) -> None:
        created = self._service.create_access_key(
            "limited",
            api_key="sk-limited",
            model_permissions=["demo/gpt-4.1-mini"],
        )
        resolved = self._service.get_access_key(created["id"])

        self.assertFalse(self._service.can_access_key_access_model(resolved, "demo/gpt-4.1"))
        self.assertTrue(self._service.can_access_key_access_model(resolved, "demo/gpt-4.1-mini"))

    def test_log_service_records_api_key_dimension(self) -> None:
        log_repository = LogRepository(self._get_connection)
        log_service = LogService(self._ctx, log_repository)
        created = self._service.create_access_key("stats", api_key="sk-stats")

        log_service.log_request(
            request_model="demo/gpt-4.1",
            response_model="gpt-4.1",
            total_tokens=10,
            prompt_tokens=4,
            completion_tokens=6,
            start_time=now_local_datetime(),
            end_time=now_local_datetime(),
            ip_address="10.0.0.9",
            api_key_id=created["id"],
        )

        stats = log_service.get_statistics()
        logs = log_service.get_request_logs()

        self.assertEqual(created["id"], stats[0]["api_key_id"])
        self.assertEqual("stats", stats[0]["api_key_name"])
        self.assertEqual(created["id"], logs["logs"][0]["api_key_id"])
        self.assertEqual("stats", logs["logs"][0]["api_key_name"])
