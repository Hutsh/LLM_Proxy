#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""数据面访问密钥服务。"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import string
from collections.abc import Iterable, Sequence
from typing import Any

from ..application.app_context import AppContext
from ..config.provider_config import normalize_model_list
from ..repositories import AccessKeyRepository
from ..utils.local_time import normalize_local_datetime_text


class AccessKeyService:
    """封装数据面访问密钥创建、校验与模型授权。"""

    MODEL_PERMISSIONS_ALL = AccessKeyRepository.MODEL_PERMISSIONS_ALL
    KEY_PREFIX = "sk-"
    _CUSTOM_KEY_CHARS = set(string.ascii_letters + string.digits + "_-.")

    def __init__(self, ctx: AppContext, repository: AccessKeyRepository):
        self._logger = ctx.logger
        self._config_manager = ctx.config_manager
        self._repository = repository

    @staticmethod
    def _hash_key(api_key: str) -> str:
        """对密钥做不可逆哈希，用于请求阶段快速匹配。"""
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    @classmethod
    def _mask_key(cls, api_key: str) -> str:
        """生成可展示的脱敏密钥。"""
        if len(api_key) <= 12:
            return f"{cls.KEY_PREFIX}***"
        return f"{api_key[:7]}...{api_key[-4:]}"

    @staticmethod
    def _dedupe_models(model_names: Iterable[Any]) -> list[str]:
        seen_models: set[str] = set()
        normalized_models: list[str] = []
        for item in model_names:
            model_name = str(item or "").strip()
            if not model_name or model_name in seen_models:
                continue
            seen_models.add(model_name)
            normalized_models.append(model_name)
        return normalized_models

    def _get_available_model_names(self) -> tuple[str, ...]:
        """读取配置中声明的模型列表，包含已禁用 Provider 的模型。"""
        try:
            config = self._config_manager.get_raw_config()
        except Exception as exc:
            self._logger.error("Failed to load config model catalog: %s", exc)
            return ()

        raw_providers = config.get("providers", [])
        if raw_providers is None or not isinstance(raw_providers, list):
            return ()

        model_names: list[str] = []
        seen_models: set[str] = set()
        for raw_provider in raw_providers:
            if not isinstance(raw_provider, dict):
                continue
            provider_name = str(raw_provider.get("name") or "").strip()
            if not provider_name:
                continue
            try:
                provider_models = normalize_model_list(raw_provider.get("model_list"))
            except ValueError:
                continue
            for provider_model in provider_models:
                model_key = f"{provider_name}/{provider_model}"
                if model_key in seen_models:
                    continue
                seen_models.add(model_key)
                model_names.append(model_key)
        return tuple(sorted(model_names))

    @classmethod
    def _deserialize_model_permissions(cls, raw_value: Any) -> tuple[str, ...] | None:
        """反序列化模型权限；返回 None 表示通配全模型。"""
        normalized_text = str(raw_value or "").strip()
        if not normalized_text or normalized_text == cls.MODEL_PERMISSIONS_ALL:
            return None

        try:
            payload = json.loads(normalized_text)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = normalized_text.replace(",", "\n").splitlines()

        if isinstance(payload, str):
            payload = [payload]
        if not isinstance(payload, list):
            return ()

        normalized_models = cls._dedupe_models(payload)
        if cls.MODEL_PERMISSIONS_ALL in normalized_models:
            return None
        return tuple(normalized_models)

    def _serialize_model_permissions(self, value: Any) -> str:
        """标准化模型权限存储格式。"""
        if value is None:
            return self.MODEL_PERMISSIONS_ALL
        if isinstance(value, str):
            normalized_text = value.strip()
            if not normalized_text or normalized_text == self.MODEL_PERMISSIONS_ALL:
                return self.MODEL_PERMISSIONS_ALL
            raw_items: Sequence[Any] = normalized_text.replace(",", "\n").splitlines()
        elif isinstance(value, (list, tuple, set)):
            raw_items = list(value)
        else:
            raise ValueError('model_permissions must be "*" or a list of model names')

        normalized_models = self._dedupe_models(raw_items)
        if self.MODEL_PERMISSIONS_ALL in normalized_models:
            return self.MODEL_PERMISSIONS_ALL

        available_models = set(self._get_available_model_names())
        unknown_models = [model for model in normalized_models if model not in available_models]
        if unknown_models:
            raise ValueError(f"Unknown model permission(s): {', '.join(unknown_models)}")

        return json.dumps(normalized_models, ensure_ascii=True)

    def _decorate_access_key(self, access_key: dict[str, Any] | None) -> dict[str, Any] | None:
        """补充访问密钥展示字段。"""
        if not access_key:
            return access_key

        normalized = dict(access_key)
        parsed_permissions = self._deserialize_model_permissions(normalized.get("model_permissions"))
        available_models = self._get_available_model_names()
        available_model_set = set(available_models)
        if parsed_permissions is None:
            normalized["model_permissions"] = self.MODEL_PERMISSIONS_ALL
            normalized["model_permissions_mode"] = "all"
            normalized["allowed_models_count"] = len(available_models)
        else:
            filtered_permissions = [
                model_name
                for model_name in parsed_permissions
                if not available_model_set or model_name in available_model_set
            ]
            normalized["model_permissions"] = filtered_permissions
            normalized["model_permissions_mode"] = "selected"
            normalized["allowed_models_count"] = len(filtered_permissions)

        normalized["access_enabled"] = bool(normalized.get("access_enabled"))
        normalized["api_key"] = str(normalized.get("key_value") or "")
        normalized.pop("key_value", None)
        normalized["available_models_count"] = len(available_models)
        normalized["created_at"] = normalize_local_datetime_text(normalized.get("created_at"))
        normalized["updated_at"] = normalize_local_datetime_text(normalized.get("updated_at"))
        return normalized

    def _ensure_copyable_access_key(self, access_key: dict[str, Any]) -> dict[str, Any]:
        """为历史密钥补齐可复制明文。"""
        if str(access_key.get("key_value") or "").strip():
            return access_key

        key_id = int(access_key.get("id") or 0)
        name = str(access_key.get("name") or "").strip()
        for _ in range(5):
            replacement_key = self.generate_key()
            try:
                if self._repository.update_secret(
                    key_id,
                    self._hash_key(replacement_key),
                    replacement_key,
                    self._mask_key(replacement_key),
                ):
                    self._logger.warning(
                        "Access key plaintext backfilled: id=%s name=%r",
                        key_id,
                        name,
                    )
                    refreshed = self._repository.get_by_id(key_id)
                    return refreshed or access_key
            except sqlite3.IntegrityError:
                continue

        self._logger.error("Failed to backfill access key plaintext: id=%s name=%r", key_id, name)
        return access_key

    @classmethod
    def _normalize_custom_key(cls, raw_key: Any) -> str | None:
        """校验并标准化自定义访问密钥。"""
        if raw_key is None:
            return None
        api_key = str(raw_key or "").strip()
        if not api_key:
            return None
        if not api_key.startswith(cls.KEY_PREFIX):
            raise ValueError('api_key must start with "sk-"')
        if len(api_key) < 8:
            raise ValueError("api_key is too short")
        if any(char not in cls._CUSTOM_KEY_CHARS for char in api_key):
            raise ValueError("api_key contains unsupported characters")
        return api_key

    @classmethod
    def generate_key(cls) -> str:
        """生成默认 sk- 访问密钥。"""
        return f"{cls.KEY_PREFIX}{secrets.token_urlsafe(32)}"

    def create_access_key(
        self,
        name: Any,
        *,
        api_key: Any = None,
        model_permissions: Any = None,
    ) -> dict[str, Any]:
        """创建访问密钥，返回可复制的明文密钥。"""
        normalized_name = str(name or "").strip()
        if not normalized_name:
            raise ValueError("Access key name is required")

        plain_key = self._normalize_custom_key(api_key) or self.generate_key()
        serialized_permissions = self._serialize_model_permissions(model_permissions)
        try:
            key_id = self._repository.create(
                normalized_name,
                self._hash_key(plain_key),
                plain_key,
                self._mask_key(plain_key),
                serialized_permissions,
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Access key already exists") from exc
        self._logger.info("Access key created: id=%s name=%r", key_id, normalized_name)
        created = self._decorate_access_key(self._repository.get_by_id(key_id)) or {}
        created["api_key"] = plain_key
        return created

    def list_access_keys(self) -> list[dict[str, Any]]:
        """列出访问密钥。"""
        rows = [self._ensure_copyable_access_key(row) for row in self._repository.list_all()]
        return [item for item in (self._decorate_access_key(row) for row in rows) if item]

    def get_available_models(self) -> list[str]:
        """返回当前配置中可选的模型列表。"""
        return list(self._get_available_model_names())

    def get_access_key(self, key_id: int) -> dict[str, Any] | None:
        """按 ID 查询访问密钥。"""
        access_key = self._repository.get_by_id(key_id)
        if access_key:
            access_key = self._ensure_copyable_access_key(access_key)
        return self._decorate_access_key(access_key)

    def get_access_key_by_token(self, api_key: str | None) -> dict[str, Any] | None:
        """按明文 token 查询启用中的访问密钥。"""
        normalized_key = self._normalize_custom_key(api_key)
        if not normalized_key:
            return None
        access_key = self._repository.get_by_hash(self._hash_key(normalized_key))
        if not access_key or not bool(access_key.get("access_enabled")):
            return None
        if not str(access_key.get("key_value") or "").strip():
            self._repository.update_secret(
                int(access_key["id"]),
                self._hash_key(normalized_key),
                normalized_key,
                self._mask_key(normalized_key),
            )
            access_key = self._repository.get_by_id(int(access_key["id"])) or access_key
        return self._decorate_access_key(access_key)

    def update_access_key(
        self,
        key_id: int,
        *,
        name: Any = None,
        access_enabled: Any = None,
        model_permissions_provided: bool = False,
        model_permissions: Any = None,
    ) -> bool:
        """更新访问密钥元数据。"""
        if not self._repository.get_by_id(key_id):
            return False

        normalized_name = None
        if name is not None:
            normalized_name = str(name or "").strip()
            if not normalized_name:
                raise ValueError("Access key name is required")

        normalized_enabled = None
        if access_enabled is not None:
            normalized_enabled = bool(access_enabled)

        serialized_permissions = None
        if model_permissions_provided:
            serialized_permissions = self._serialize_model_permissions(model_permissions)

        return self._repository.update(
            key_id,
            name=normalized_name,
            access_enabled=normalized_enabled,
            model_permissions=serialized_permissions,
        )

    def toggle_access_key(self, key_id: int) -> bool:
        """切换访问密钥启用状态。"""
        access_key = self._repository.get_by_id(key_id)
        if not access_key:
            return False
        return self._repository.update(key_id, access_enabled=not bool(access_key.get("access_enabled")))

    def delete_access_key(self, key_id: int) -> bool:
        """删除访问密钥。"""
        return self._repository.delete(key_id)

    def get_accessible_models_for_key(
        self,
        access_key: dict[str, Any] | None,
        available_models: Sequence[str] | None = None,
    ) -> list[str]:
        """返回访问密钥在给定模型集合内可访问的模型。"""
        if not access_key:
            return []

        resolved_available_models = list(
            self._get_available_model_names() if available_models is None else available_models
        )
        permissions = access_key.get("model_permissions")
        if permissions == self.MODEL_PERMISSIONS_ALL or access_key.get("model_permissions_mode") == "all":
            return resolved_available_models

        if isinstance(permissions, list):
            explicit_models = self._dedupe_models(permissions)
        else:
            parsed_permissions = self._deserialize_model_permissions(permissions)
            if parsed_permissions is None:
                return resolved_available_models
            explicit_models = list(parsed_permissions)

        if not resolved_available_models:
            return explicit_models

        available_model_set = set(resolved_available_models)
        return [model_name for model_name in explicit_models if model_name in available_model_set]

    def can_access_key_access_model(
        self,
        access_key: dict[str, Any] | None,
        model_name: str,
        available_models: Sequence[str] | None = None,
    ) -> bool:
        """判断访问密钥是否可访问指定模型。"""
        normalized_model_name = str(model_name or "").strip()
        if not normalized_model_name or not access_key:
            return False
        return normalized_model_name in set(
            self.get_accessible_models_for_key(access_key, available_models=available_models)
        )
