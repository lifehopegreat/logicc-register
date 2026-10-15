import shutil
import subprocess
from pathlib import Path


def test_failure_labels_explain_service_errors_without_changing_task_state():
    source = Path(__file__).resolve().parents[1] / "static" / "app.js"
    script = r'''
const assert = require("node:assert/strict");
const vm = require("node:vm");
const source = require("node:fs").readFileSync(process.argv[1], "utf8");
const nodes = {};
const document = {querySelector: id => nodes[id] ||= {}};
const context = vm.createContext({document});
vm.runInContext(source.split("function rollingNumber")[0] +
  source.slice(source.indexOf("function renderBatchTable"), source.indexOf("async function loadBatch")), context);
const cases = [
  ["ERROR_CAPTCHA_UNSOLVABLE", "求解服务失败", "不保证"],
  ["capmonster_poll_timeout", "求解查询超时", "不等于"],
  ["network_unavailable", "网络连接失败", "阶段"],
  ["upstream_unavailable", "上游服务异常", "阶段"],
  ["capmonster_attempt_already_used", "付费任务保护", "回执"],
];
for (const [error, label, explanation] of cases) {
  const row = {state: "human_required", error, step: "solve_captcha", email: "fixture@example.test"};
  context.row = row;
  const before = JSON.stringify(row);
  const output = vm.runInContext("resultPresentation(row.state, row)", context);
  assert.equal(output.label, label);
  assert.ok(output.detail.includes(error) && output.detail.includes(explanation));
  vm.runInContext("renderBatchTable({accounts:[row]})", context);
  assert.ok(nodes["#batchTableBody"].innerHTML.includes(label));
  assert.equal(JSON.stringify(row), before);
}
assert.equal(vm.runInContext('resultPresentation("human_required", {error:"captcha_required"}).label', context), "需要人工");
assert.equal(vm.runInContext('resultPresentation("completed", {error:"ERROR_CAPTCHA_UNSOLVABLE"}).label', context), "已确认完成");
assert.equal(vm.runInContext('resultPresentation("partial", {error:"__proto__"}).label', context), "部分完成");
context.row = {state:"partial", error:"<script>untrusted</script>"};
vm.runInContext("renderBatchTable({accounts:[row]})", context);
assert.ok(!nodes["#batchTableBody"].innerHTML.includes("<script>"));
'''
    result = subprocess.run([shutil.which("node") or "node", "-e", script, str(source)],
                            capture_output=True, text=True, encoding="utf-8", timeout=15)
    assert result.returncode == 0, result.stderr
