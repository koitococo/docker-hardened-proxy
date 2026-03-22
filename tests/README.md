# 集成测试约定

本目录用于存放 `docker-hardened-proxy` 的集成测试用例。

## 基本约定

- 上游 Docker daemon 必须通过 `DOCKER_HOST` 环境变量指定。
- 每个测试用例必须位于独立目录：`tests/<test_name>/`。
- 每个测试目录必须至少包含：
  - `config.yaml`
  - `run_test.py` 或 `run_test.ts`
- 每个测试必须独立创建并清理自己的资源，避免与其他测试共享状态。

## 推荐执行方式

- 单用例执行：进入 `tests/` 目录后运行 `uv run python3 <test_name>/run_test.py`。
- 全量执行：在 `tests/` 目录运行 `uv run python3 run_all.py`。

## 环境变量

- `DOCKER_HOST`: 上游 Docker daemon 地址，例如：
  - `unix:///home/ubuntu/.run/docker.sock`
  - `unix:///var/run/docker.sock`
  - `tcp://127.0.0.1:2375`

如果未设置 `DOCKER_HOST`，测试脚本应直接失败并给出明确提示。

## 依赖管理

- Python 依赖通过 `uv` 管理。
- 初始化依赖：`uv sync`
- 所有测试应优先使用 `uv run` 执行，确保依赖版本一致。
