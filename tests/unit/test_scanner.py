from __future__ import annotations

import pytest

from api_testing_agent.errors import FrameworkNotIdentifiedError, InvalidInputError
from api_testing_agent.scanner.repository_scanner import scan_repository, select_backend
from tests.conftest import write_files

LARAVEL = {
    "composer.json": '{"require": {"laravel/framework": "^10"}}',
    "artisan": "#!/usr/bin/env php\n<?php\n",
    "routes/api.php": "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/ping', fn () => 'pong');\n",
}
EXPRESS = {
    "package.json": '{"dependencies": {"express": "^4"}}',
    "server.js": "const express = require('express');\nconst app = express();\napp.get('/x', (req,res)=>{});\n",
}
SPRING = {
    "pom.xml": "<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>",
    "src/main/java/A.java": '@RestController\nclass A { @GetMapping("/x") String g(){return "";} }',
}
DOTNET = {
    "Api.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    "Controllers/A.cs": "[ApiController]\npublic class AController : ControllerBase { }",
}
GO = {
    "go.mod": "module x\nrequire github.com/gin-gonic/gin v1.9.0\n",
    "main.go": 'package main\nimport "github.com/gin-gonic/gin"\nfunc main(){ r := gin.Default(); r.GET("/p", h) }',
}
DJANGO = {
    "manage.py": "import django\n",
    "requirements.txt": "django>=4\n",
    "proj/urls.py": "from django.urls import path\nurlpatterns = []\n",
}
FLASK = {"requirements.txt": "flask\n", "app.py": "from flask import Flask\napp = Flask(__name__)\n"}
FASTAPI = {"requirements.txt": "fastapi\n", "main.py": "from fastapi import FastAPI\napp = FastAPI()\n"}


@pytest.mark.parametrize(
    "files,framework,language",
    [(LARAVEL, "Laravel", "php"), (EXPRESS, "Express", "javascript"), (SPRING, "Spring", "java"),
     (DOTNET, "ASP.NET Core", "csharp"), (GO, "Gin", "go"), (DJANGO, "Django", "python"),
     (FLASK, "Flask", "python"), (FASTAPI, "FastAPI", "python")],
)
def test_framework_detection_with_evidence(tmp_path, files, framework, language):
    write_files(tmp_path, files)
    scan = scan_repository(tmp_path)
    match = [b for b in scan.backends if b.framework == framework]
    assert match, f"{framework} not detected: {scan.backends}"
    assert match[0].language == language
    assert match[0].evidence, "every detection must record its evidence"


def test_invalid_folder_is_rejected(tmp_path):
    with pytest.raises(InvalidInputError):
        scan_repository(tmp_path / "missing")
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(InvalidInputError):
        scan_repository(f)


def test_manifest_without_backend_is_not_a_backend(tmp_path):
    write_files(tmp_path, {"package.json": '{"dependencies": {"react": "18"}}', "src/app.js": "console.log(1)"})
    scan = scan_repository(tmp_path)
    assert scan.backends == []
    assert any("No backend" in w for w in scan.warnings)
    with pytest.raises(FrameworkNotIdentifiedError):
        select_backend(scan)


def test_multiple_backends_require_explicit_selection(tmp_path):
    files = {f"api/{k}": v for k, v in EXPRESS.items()} | {f"svc/{k}": v for k, v in FASTAPI.items()}
    write_files(tmp_path, files)
    scan = scan_repository(tmp_path)
    assert scan.multiple_backends
    assert {b.path for b in scan.backends} == {"api", "svc"}
    with pytest.raises(InvalidInputError, match="Multiple backend"):
        select_backend(scan)
    assert select_backend(scan, backend="svc").framework == "FastAPI"
    with pytest.raises(InvalidInputError):
        select_backend(scan, backend="nope")


def test_dependency_and_build_dirs_are_excluded(tmp_path):
    write_files(tmp_path, {
        **FASTAPI,
        "node_modules/express/index.js": "const express = require('express');",
        "vendor/laravel/x.php": "<?php Route::get('/v', fn()=>1);",
        ".git/config": "x",
    })
    scan = scan_repository(tmp_path)
    assert {b.framework for b in scan.backends} == {"FastAPI"}


def test_only_real_openapi_documents_count_as_specs(tmp_path):
    write_files(tmp_path, {
        **FASTAPI,
        "openapi.yaml": "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths: {}\n",
        "config.json": '{"openapi_mode": "strict", "note": "mentions openapi"}',
        "data.yaml": "swagger_ui: true\n",
    })
    scan = scan_repository(tmp_path)
    assert [s.path for s in scan.spec_files] == ["openapi.yaml"]
