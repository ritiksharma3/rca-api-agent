from __future__ import annotations

import pytest

from api_testing_agent.discovery.base import DiscoveryContext
from api_testing_agent.discovery.python_static import PythonStaticAdapter
from api_testing_agent.discovery.static_adapter import TreeSitterStaticAdapter
from api_testing_agent.scanner.repository_scanner import scan_repository, select_backend
from tests.conftest import write_files


def discover(tmp_path, files, adapter):
    write_files(tmp_path, files)
    scan = scan_repository(tmp_path)
    backend = select_backend(scan)
    ctx = DiscoveryContext(root=tmp_path, scan=scan, backend=backend)
    assert adapter.applicable(ctx).ok
    out = adapter.discover(ctx)
    return {(e.method, e.route): e for e in out.endpoints}, out


# ------------------------------------------------------------------ Python
def test_fastapi_prefixes_models_auth_and_dynamic_routes(tmp_path):
    files = {
        "requirements.txt": "fastapi\n",
        "app/__init__.py": "",
        "app/models.py": (
            "from pydantic import BaseModel, Field\n"
            "class UserIn(BaseModel):\n"
            "    email: str = Field(..., min_length=3)\n"
            "    age: int = Field(18, ge=0, le=150)\n"
            "    nick: str | None = None\n"
        ),
        "app/routers/__init__.py": "",
        "app/routers/users.py": (
            "from fastapi import APIRouter, Depends\nfrom app.models import UserIn\n"
            "router = APIRouter(prefix='/users')\n"
            "def get_current_user(): ...\n"
            "@router.get('/{user_id}')\ndef one(user_id: int, verbose: bool = False): ...\n"
            "@router.post('', status_code=201)\ndef create(u: UserIn, me=Depends(get_current_user)): ...\n"
        ),
        "app/main.py": (
            "from fastapi import FastAPI\nfrom app.routers import users\n"
            "app = FastAPI()\napp.include_router(users.router, prefix='/api/v1')\n"
            "for n in ['a','b']:\n    app.add_api_route(f'/dyn/{n}', lambda: 1, methods=['GET'])\n"
        ),
    }
    by, out = discover(tmp_path, files, PythonStaticAdapter())
    assert set(by) == {("GET", "/api/v1/users/{user_id}"), ("POST", "/api/v1/users")}
    get = by[("GET", "/api/v1/users/{user_id}")]
    path = next(p for p in get.parameters if p.name == "user_id")
    assert path.schema_def["type"] == "integer"
    assert any(p.name == "verbose" and not p.required for p in get.parameters)
    post = by[("POST", "/api/v1/users")]
    body = post.request_body.schema_def
    assert body["required"] == ["email"] and body["properties"]["age"]["maximum"] == 150
    assert post.requires_auth is True
    assert any("dynamic" in p.reason for p in out.potential_routes), "dynamic registrations must surface as NOT DISCOVERED"


def test_flask_blueprint_prefix_and_methods(tmp_path):
    files = {
        "requirements.txt": "flask\n",
        "app.py": (
            "from flask import Flask, Blueprint, request\n"
            "app = Flask(__name__)\nbp = Blueprint('api', __name__, url_prefix='/api')\n"
            "@bp.route('/items/<int:item_id>', methods=['GET', 'DELETE'])\ndef item(item_id): ...\n"
            "@bp.post('/items')\ndef make():\n    d = request.get_json()\n    q = request.args.get('flag')\n"
            "app.register_blueprint(bp)\n"
        ),
    }
    by, out = discover(tmp_path, files, PythonStaticAdapter())
    assert set(by) == {("GET", "/api/items/{item_id}"), ("DELETE", "/api/items/{item_id}"), ("POST", "/api/items")}
    assert by[("GET", "/api/items/{item_id}")].parameters[0].schema_def["type"] == "integer"
    assert any(p.name == "flag" for p in by[("POST", "/api/items")].parameters)
    assert any("JSON body" in w for w in by[("POST", "/api/items")].warnings)


def test_django_include_and_view_methods(tmp_path):
    files = {
        "manage.py": "import django\n",
        "proj/__init__.py": "",
        "proj/settings.py": "ROOT_URLCONF = 'proj.urls'\n",
        "proj/urls.py": "from django.urls import path, include\nurlpatterns = [path('api/', include('shop.urls')), path('admin/', include(admin_urls))]\n",
        "shop/__init__.py": "",
        "shop/views.py": (
            "from rest_framework.decorators import api_view\nfrom django.views import View\n"
            "@api_view(['GET', 'POST'])\ndef products(request): ...\n"
            "def plain(request): ...\n"
            "class Detail(View):\n    def get(self, r, pk): ...\n    def delete(self, r, pk): ...\n"
        ),
        "shop/urls.py": (
            "from django.urls import path\nfrom . import views\n"
            "urlpatterns = [path('products/', views.products), path('plain/', views.plain), path('p/<int:pk>/', views.Detail.as_view())]\n"
        ),
    }
    by, out = discover(tmp_path, files, PythonStaticAdapter())
    assert ("GET", "/api/products") in by and ("POST", "/api/products") in by
    assert by[("GET", "/api/plain")].confidence.value == "low"
    assert ("DELETE", "/api/p/{pk}") in by
    assert out.potential_routes, "include() of a non-static target must be reported as unresolved"


# ------------------------------------------------------------------ tree-sitter languages
def test_laravel_groups_prefixes_resources_and_auth(tmp_path):
    files = {
        "composer.json": '{"require": {"laravel/framework": "^10"}}',
        "artisan": "<?php\n",
        "routes/api.php": (
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n"
            "Route::get('/ping', [PingController::class, 'index']);\n"
            "Route::prefix('v1')->middleware('auth:sanctum')->group(function () {\n"
            "    Route::get('/users/{id}', [UserController::class, 'show']);\n"
            "    Route::post('/users', [UserController::class, 'store'])->name('users.store');\n"
            "    Route::apiResource('photos', PhotoController::class)->only(['index', 'show']);\n"
            "});\n"
            "Route::get($dynamic, fn() => 1);\n"
        ),
    }
    by, out = discover(tmp_path, files, TreeSitterStaticAdapter())
    assert ("GET", "/api/ping") in by
    assert by[("GET", "/api/v1/users/{id}")].requires_auth is True
    assert ("POST", "/api/v1/users") in by
    assert ("GET", "/api/v1/photos") in by and ("GET", "/api/v1/photos/{photo}") in by
    assert ("DELETE", "/api/v1/photos/{photo}") not in by, "->only() must restrict resource expansion"
    assert any("not a static string" in p.reason for p in out.potential_routes)


def test_express_router_mounting_and_body_inference(tmp_path):
    files = {
        "package.json": '{"dependencies": {"express": "4"}}',
        "routes/users.js": (
            "const express = require('express');\nconst router = express.Router();\n"
            "router.get('/:id', (req, res) => { const q = req.query.expand; res.json({}); });\n"
            "router.post('/', requireAuth, (req, res) => { const { name, email } = req.body; });\n"
            "module.exports = router;\n"
        ),
        "app.js": "const express = require('express');\nconst users = require('./routes/users');\nconst app = express();\napp.use('/api/users', users);\napp.get('/health', (req, res) => {});\n",
    }
    by, out = discover(tmp_path, files, TreeSitterStaticAdapter())
    assert set(by) == {("GET", "/api/users/{id}"), ("POST", "/api/users"), ("GET", "/health")}
    assert by[("POST", "/api/users")].requires_auth is True
    assert set(by[("POST", "/api/users")].request_body.schema_def["properties"]) == {"name", "email"}
    assert any(p.name == "expand" for p in by[("GET", "/api/users/{id}")].parameters)


def test_spring_annotations_and_dto_constraints(tmp_path):
    files = {
        "pom.xml": "<project>spring-boot-starter-web</project>",
        "src/main/java/NewUser.java": (
            "class NewUser { @NotBlank @Size(min = 2, max = 20) private String name; @Min(0) private int age; }"
        ),
        "src/main/java/UserController.java": (
            '@RestController\n@RequestMapping("/api/users")\nclass UserController {\n'
            '  @GetMapping("/{id}") public String get(@PathVariable Long id, @RequestParam(required = false) String q){return "";}\n'
            '  @PostMapping @PreAuthorize("hasRole(\'ADMIN\')") public String create(@RequestBody NewUser u){return "";}\n'
            '  @DeleteMapping("/{id}") public void del(@PathVariable("id") Long id){}\n}\n'
        ),
    }
    by, out = discover(tmp_path, files, TreeSitterStaticAdapter())
    assert set(by) == {("GET", "/api/users/{id}"), ("POST", "/api/users"), ("DELETE", "/api/users/{id}")}
    assert next(p for p in by[("GET", "/api/users/{id}")].parameters if p.name == "id").schema_def["type"] == "integer"
    post = by[("POST", "/api/users")]
    assert post.requires_auth is True
    assert post.request_body.schema_def["required"] == ["name"]
    assert post.request_body.schema_def["properties"]["name"]["maxLength"] == 20


def test_aspnet_controller_and_minimal_api(tmp_path):
    files = {
        "Api.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"/>',
        "Controllers/ProductsController.cs": (
            'using System;\n[ApiController]\n[Route("api/[controller]")]\n[Authorize]\n'
            "public class ProductsController : ControllerBase {\n"
            '  [HttpGet("{id:int}")] public IActionResult Get(int id) { return null; }\n'
            "  [HttpPost] public IActionResult Create([FromBody] ProductDto dto) { return null; }\n"
            '  [AllowAnonymous][HttpGet("public")] public IActionResult Pub() { return null; }\n}\n'
            "public class ProductDto { [Required] public string Name { get; set; } [Range(1, 100)] public int Qty { get; set; } }\n"
        ),
        "Program.cs": 'var app = WebApplication.Create(args);\napp.MapGet("/ping", () => "pong");\napp.Run();\n',
    }
    by, out = discover(tmp_path, files, TreeSitterStaticAdapter())
    assert ("GET", "/api/products/{id}") in by and ("POST", "/api/products") in by and ("GET", "/ping") in by
    assert by[("GET", "/api/products/{id}")].requires_auth is True
    assert by[("GET", "/api/products/public")].requires_auth is False
    body = by[("POST", "/api/products")].request_body.schema_def
    assert body["required"] == ["name"] and body["properties"]["qty"]["maximum"] == 100.0


def test_go_gin_groups_and_net_http(tmp_path):
    files = {
        "go.mod": "module x\nrequire github.com/gin-gonic/gin v1.9.0\n",
        "main.go": (
            'package main\nimport "github.com/gin-gonic/gin"\nfunc main() {\n'
            '  r := gin.Default()\n  api := r.Group("/api")\n  api.GET("/users/:id", h)\n  api.POST("/users", h)\n'
            '  http.HandleFunc("GET /legacy/{id}", h)\n}\n'
        ),
    }
    by, out = discover(tmp_path, files, TreeSitterStaticAdapter())
    assert ("GET", "/api/users/{id}") in by and ("POST", "/api/users") in by and ("GET", "/legacy/{id}") in by
    assert all(e.confidence.value != "high" for e in by.values()), "Go analysis is shallower and must not claim high confidence"


def test_laravel_route_files_included_from_a_group_inherit_prefix_and_auth(tmp_path):
    files = {
        "composer.json": '{"require": {"laravel/framework": "^10"}}',
        "artisan": "<?php\n",
        "routes/api.php": (
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n"
            "Route::post('/auth/login', [AuthController::class, 'login']);\n"
            "Route::group(['middleware' => ['auth:sanctum', 'throttle:120,1']], function () {\n"
            "    Route::name('employees')->group(base_path('app/Api/Employee/EmployeeRoute.php'));\n"
            "    Route::prefix('hr')->group(base_path('app/Api/Hr/HrRoute.php'));\n"
            "});\n"
            "Route::group(['prefix' => 'public'], function () { require base_path('app/Api/Open/OpenRoute.php'); });\n"
            "Route::name('x')->group(base_path('../outside.php'));\n"
            "Route::name('y')->group($dynamicPath);\n"
        ),
        "app/Api/Employee/EmployeeRoute.php": (
            "<?php\nRoute::get('/employees/list', [EmployeeController::class, 'list']);\n"
            "Route::group(['middleware' => ['permission:Approve Employee']], function () {\n"
            "    Route::post('/employees/approval', [EmployeeController::class, 'approve']);\n"
            "});\n"
            "Route::delete('/employees/{uuid}', [EmployeeController::class, 'destroy']);\n"
        ),
        "app/Api/Hr/HrRoute.php": "<?php\nRoute::get('/staff', [HrController::class, 'index']);\nRoute::name('deep')->group(base_path('app/Api/Hr/DeepRoute.php'));\n",
        "app/Api/Hr/DeepRoute.php": "<?php\nRoute::get('/deep', [HrController::class, 'deep']);\nRoute::name('loop')->group(base_path('app/Api/Hr/HrRoute.php'));\n",
        "app/Api/Open/OpenRoute.php": "<?php\nRoute::get('/ping', [OpenController::class, 'ping']);\n",
        "outside.php": "<?php\nRoute::get('/leak', fn() => 1);\n",
    }
    by, out = discover(tmp_path, files, TreeSitterStaticAdapter())
    assert by[("GET", "/api/employees/list")].requires_auth is True, "auth:sanctum comes from the including group"
    assert ("POST", "/api/employees/approval") in by and by[("POST", "/api/employees/approval")].requires_auth is True
    assert ("DELETE", "/api/employees/{uuid}") in by
    assert ("GET", "/api/hr/staff") in by and ("GET", "/api/hr/deep") in by, "prefix flows through nested includes"
    assert by[("GET", "/api/public/ping")].requires_auth is None, "an include outside the auth group stays public"
    assert by[("POST", "/api/auth/login")].requires_auth is None
    assert not any("leak" in r for _m, r in by), "an include that escapes the project root must never be read"
    assert any("not static" in p.reason or "does not exist" in p.reason for p in out.potential_routes)
    assert any("followed" in w.message for w in out.warnings)
    assert len([k for k in by if k[1] == "/api/hr/staff"]) == 1, "include cycles must not duplicate routes"
