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

- 单用例执行：进入测试目录后运行对应脚本。
- 全量执行：后续统一通过 `tests/run_all.py` 执行。

## 环境变量

- `DOCKER_HOST`: 上游 Docker daemon 地址，例如：
  - `unix:///home/ubuntu/.run/docker.sock`
  - `unix:///var/run/docker.sock`
  - `tcp://127.0.0.1:2375`

如果未设置 `DOCKER_HOST`，测试脚本应直接失败并给出明确提示。
