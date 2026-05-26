"""Tests for scope validation."""
import pytest

from enshroud.scope import load_scope, target_in_scope, get_target_host


def test_load_scope(scope_file):
    entries = load_scope(scope_file)
    assert "127.0.0.1" in entries
    assert "localhost" in entries


def test_target_in_scope_by_ip():
    assert target_in_scope("http://127.0.0.1:8080/graphql", ["127.0.0.1"])


def test_target_in_scope_by_hostname():
    assert target_in_scope("http://api.example.com/graphql", ["api.example.com"])


def test_target_in_scope_subdomain():
    assert target_in_scope("http://api.example.com/graphql", ["example.com"])


def test_target_out_of_scope():
    assert not target_in_scope("http://evil.com/graphql", ["example.com"])


def test_target_in_scope_cidr():
    assert target_in_scope("http://10.0.0.5/graphql", ["10.0.0.0/24"])


def test_target_out_of_scope_cidr():
    assert not target_in_scope("http://10.0.1.5/graphql", ["10.0.0.0/24"])


def test_scope_file_comments(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("# comment\nexample.com\n# another comment\n")
    entries = load_scope(str(scope))
    assert entries == ["example.com"]


def test_get_target_host():
    assert get_target_host("http://api.example.com:8080/graphql") == "api.example.com"
