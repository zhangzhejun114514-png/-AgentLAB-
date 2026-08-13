"""
AgentLAB 可视化运行界面
基于 Gradio 的 Web UI，用于浏览数据集、配置参数和运行攻击脚本
"""
import json
import os
import sys
import subprocess
import threading
import time
from pathlib import Path
from collections import Counter
import pandas as pd

import gradio as gr

AGENTLAB_DIR = Path(__file__).parent

# ==========================================
# 数据加载
# ==========================================
def load_json(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_datasets():
    datasets = {}
    p1 = AGENTLAB_DIR / "data" / "filtered_top_200_attacks.json"
    p2 = AGENTLAB_DIR / "data" / "all_refused_combined_200.json"
    p3 = AGENTLAB_DIR / "Agent_SafetyBench" / "data" / "released_data.json"
    if p1.exists():
        datasets["Intent Hijacking (200)"] = p1
    if p2.exists():
        datasets["Memory Poisoning (200)"] = p2
    if p3.exists():
        datasets["Agent_SafetyBench (2000)"] = p3
    return datasets

DATASETS = get_datasets()

# ==========================================
# 数据集浏览
# ==========================================
def get_dataset_overview(dataset_name):
    if not dataset_name or dataset_name not in DATASETS:
        return "请选择数据集", pd.DataFrame(), ""
    filepath = DATASETS[dataset_name]
    data = load_json(filepath)
    total = len(data)

    stats_lines = [f"### {dataset_name}\n"]
    stats_lines.append(f"- **文件**: `{filepath.name}`")
    stats_lines.append(f"- **总样本数**: {total}")
    stats_lines.append(f"- **文件大小**: {filepath.stat().st_size / 1024:.1f} KB\n")

    if "filtered_top_200" in filepath.name:
        ds_counter = Counter()
        env_counter = Counter()
        mal_scores = []
        comp_scores = []
        tool_chain_lens = []
        for item in data:
            gc = item.get("generation_config", {})
            ds_counter[gc.get("dataset", "?")] += 1
            env_counter[gc.get("environment", "?")] += 1
            mal_scores.append(item.get("malicious_score", 0))
            comp_scores.append(item.get("completion_score", 0))
            tc = item.get("attack_plan", {}).get("verified_tool_chain", [])
            tool_chain_lens.append(len(tc))

        stats_lines.append("### 数据来源")
        for k, v in ds_counter.most_common():
            stats_lines.append(f"- {k}: {v}")
        stats_lines.append("\n### 环境分布 (Top 10)")
        for k, v in env_counter.most_common(10):
            stats_lines.append(f"- {k}: {v}")
        stats_lines.append(f"\n### 评分统计")
        stats_lines.append(f"- 恶意评分: 平均 {sum(mal_scores)/len(mal_scores):.2f}")
        stats_lines.append(f"- 完成评分: 平均 {sum(comp_scores)/len(comp_scores):.2f}")
        stats_lines.append(f"- 工具链长度: 平均 {sum(tool_chain_lens)/len(tool_chain_lens):.1f}")

        rows = []
        for i, item in enumerate(data):
            rows.append({
                "ID": item.get("original_id", i),
                "来源": item.get("generation_config", {}).get("dataset", "?"),
                "环境": item.get("generation_config", {}).get("environment", "?"),
                "恶意评分": item.get("malicious_score", 0),
                "完成评分": item.get("completion_score", 0),
                "加权评分": item.get("weighted_score", 0),
                "工具链步数": len(item.get("attack_plan", {}).get("verified_tool_chain", [])),
                "攻击目标": item.get("attack_plan", {}).get("attack_goal", "")[:80],
            })
        df = pd.DataFrame(rows)

    elif "all_refused" in filepath.name:
        risk_counter = Counter()
        env_counter = Counter()
        for item in data:
            for r in item.get("risks", []):
                risk_counter[r] += 1
            for e in item.get("environments", []):
                env_counter[e.get("name", "?")] += 1

        stats_lines.append("### 风险类别")
        for k, v in risk_counter.most_common():
            stats_lines.append(f"- {k}: {v}")
        stats_lines.append("\n### 环境类型 (Top 10)")
        for k, v in env_counter.most_common(10):
            stats_lines.append(f"- {k}: {v}")

        rows = []
        for item in data:
            rows.append({
                "ID": item.get("id", 0),
                "风险": ", ".join(item.get("risks", [])),
                "环境": ", ".join([e.get("name","") for e in item.get("environments",[])]),
                "失败模式": item.get("failure_modes", ""),
                "可完成": "是" if item.get("fulfillable") == 1 else "否",
                "指令摘要": item.get("instruction", "")[:80],
            })
        df = pd.DataFrame(rows)

    elif "released_data" in filepath.name:
        risk_counter = Counter()
        env_counter = Counter()
        for item in data:
            for r in item.get("risks", []):
                risk_counter[r] += 1
            for e in item.get("environments", []):
                env_counter[e.get("name", "?")] += 1

        stats_lines.append("### 风险类别")
        for k, v in risk_counter.most_common():
            stats_lines.append(f"- {k}: {v}")
        stats_lines.append("\n### 环境类型 (Top 15)")
        for k, v in env_counter.most_common(15):
            stats_lines.append(f"- {k}: {v}")

        rows = []
        for item in data:
            rows.append({
                "ID": item.get("id", 0),
                "风险": ", ".join(item.get("risks", [])),
                "环境": ", ".join([e.get("name","") for e in item.get("environments",[])]),
                "失败模式": item.get("failure_modes", ""),
                "可完成": "是" if item.get("fulfillable") == 1 else "否",
                "指令摘要": item.get("instruction", "")[:80],
            })
        df = pd.DataFrame(rows)
    else:
        df = pd.DataFrame()

    return "\n".join(stats_lines), df, ""

def get_sample_detail(dataset_name, sample_idx):
    if not dataset_name or dataset_name not in DATASETS:
        return "请先选择数据集"
    filepath = DATASETS[dataset_name]
    data = load_json(filepath)
    try:
        idx = int(sample_idx)
        if idx < 0 or idx >= len(data):
            return f"索引超出范围 (0 ~ {len(data)-1})"
    except ValueError:
        return "请输入有效的数字索引"

    item = data[idx]
    lines = [f"### 样本 #{idx}\n"]
    lines.append(f"```json\n{json.dumps(item, indent=2, ensure_ascii=False)[:5000]}\n```")
    return "\n".join(lines)

# ==========================================
# 环境浏览
# ==========================================
def get_env_list():
    env_dir = AGENTLAB_DIR / "environments"
    jsons = sorted(env_dir.glob("*.json"))
    return [f.name for f in jsons]

def get_env_detail(env_name):
    if not env_name:
        return "请选择环境", pd.DataFrame()
    filepath = AGENTLAB_DIR / "environments" / env_name
    if not filepath.exists():
        return "环境文件不存在", pd.DataFrame()
    tools = load_json(filepath)
    info = f"### {env_name}\n- 工具数量: {len(tools)}\n"
    rows = []
    for t in tools:
        params = t.get("parameters", {}).get("properties", {})
        param_str = ", ".join(params.keys()) if params else "无"
        required = t.get("parameters", {}).get("required", [])
        rows.append({
            "工具名": t.get("name", ""),
            "描述": t.get("description", "")[:100],
            "参数": param_str,
            "必需参数": ", ".join(required) if required else "无",
        })
    return info, pd.DataFrame(rows)

# ==========================================
# 攻击运行
# ==========================================
run_process = None
run_output_lines = []

def validate_config(api_key, base_url, victim_model, attacker_url, planner_model):
    """配置验证：发送 1 次 API 调用，检查配置是否正确。成本 ~0.62 CNY。"""
    if not api_key:
        return "❌ 请先输入 API Key"

    results = []

    # 检查 base_url 是否包含错误的 /v1 后缀
    if base_url and "deepseek" in base_url and "/v1" in base_url:
        results.append(f"❌ base_url 含错误 /v1 后缀: {base_url}")
        results.append(f"   正确值应为: https://api.deepseek.com")
        return "\n".join(results)
    if attacker_url and "deepseek" in attacker_url and "/v1" in attacker_url:
        results.append(f"❌ attacker_url 含错误 /v1 后缀: {attacker_url}")
        results.append(f"   正确值应为: https://api.deepseek.com")
        return "\n".join(results)

    # 发送 1 次测试调用
    results.append(f"🔍 正在验证配置（1 次 API 调用，成本 ~0.62 CNY）...")
    results.append(f"   Victim: {victim_model}")
    results.append(f"   base_url: {base_url}")
    results.append(f"   Attacker URL: {attacker_url}")
    results.append("")

    try:
        from openai import OpenAI
        client = OpenAI(
            api_key=api_key,
            base_url=base_url or "https://api.deepseek.com"
        )
        resp = client.chat.completions.create(
            model=victim_model,
            messages=[{"role": "user", "content": "Hello, please respond with 'OK'."}],
            max_tokens=10,
            temperature=0
        )
        response_text = resp.choices[0].message.content.strip()
        results.append(f"✅ Victim 模型响应正常: \"{response_text}\"")
        results.append(f"✅ 配置验证通过！可以安全运行攻击。")
        results.append(f"💰 验证花费: ~0.62 CNY（避免了上次 500 CNY 的惨剧）")
    except Exception as e:
        results.append(f"❌ Victim 调用失败: {e}")
        results.append(f"❌ 配置验证未通过！请修复后再运行。")
        results.append(f"💡 常见问题: base_url 不要带 /v1, API Key 需有余额")

    return "\n".join(results)

def run_attack(script, api_key, base_url, victim_model, attacker_url, attacker_model,
               planner_model, num_samples, max_turns, num_strategies, success_threshold,
               no_textgrad, sequential, lightweight_mode):
    global run_process, run_output_lines
    run_output_lines = []

    if not api_key:
        return "❌ 错误: 请输入 API Key"

    # 成本警告 - 硬上限 10 CNY
    estimated_calls = num_samples * max_turns * 3 + num_strategies
    estimated_cost = num_samples * max_turns * 0.04 + num_strategies * 0.02
    if estimated_cost > 10:
        return f"❌ 预估成本 ({estimated_cost:.2f} CNY) 超过预算上限 (10.00 CNY)，请调低样本数或轮次，或开启轻量模式"
    # 额外安全阈值：超过 50 次 API 调用给出警告
    if estimated_calls > 50:
        return f"❌ 预估API调用次数 ({estimated_calls}) 过多，请调低样本数或轮次，或开启轻量模式"

    env = os.environ.copy()
    env["OPENAI_API_KEY"] = api_key
    env["DEEPSEEK_API_KEY"] = api_key
    if base_url:
        env["OPENAI_BASE_URL"] = base_url

    cmd = [sys.executable, script]
    if script == "Intent-Hijacking.py":
        cmd += ["--victim", victim_model]
        if base_url:
            cmd += ["--victim_url", base_url]
        cmd += ["--planner_judge_model", planner_model]
        if base_url:
            cmd += ["--planner_judge_url", base_url]
        if attacker_url:
            cmd += ["--attacker_url", attacker_url]
            cmd += ["--attacker_model", attacker_model or "deepseek-v4-pro"]
        cmd += ["--num_samples", str(num_samples)]
        cmd += ["--max_turns", str(max_turns)]
        cmd += ["--num_strategies", str(num_strategies)]
        cmd += ["--success_threshold", str(success_threshold)]
        if no_textgrad:
            cmd += ["--no_textgrad"]
        if sequential:
            cmd += ["--sequential"]
        if lightweight_mode:
            cmd += ["--lightweight"]
        cmd += ["--budget_cny", "10.0"]
    elif script == "Memory-Poisoning.py":
        cmd += ["--target_samples", str(num_samples)]
    elif script == "Tool-chaining.py":
        cmd += ["--victim_model", victim_model]
        cmd += ["--num_samples", str(num_samples)]
        if base_url:
            cmd += ["--victim_base_url", base_url]

    cmd_str = " ".join(cmd)
    run_output_lines.append(f"$ {cmd_str}\n")
    run_output_lines.append(f"工作目录: {AGENTLAB_DIR}\n\n")

    try:
        run_process = subprocess.Popen(
            cmd, cwd=str(AGENTLAB_DIR), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace',
            bufsize=1
        )
        for line in run_process.stdout:
            run_output_lines.append(line)
        run_process.wait()
        run_output_lines.append(f"\n[进程结束, 退出码: {run_process.returncode}]")
    except Exception as e:
        run_output_lines.append(f"\n[错误: {e}]")
    finally:
        run_process = None

    return "".join(run_output_lines)

def run_attack_async(*args):
    global run_output_lines
    run_output_lines = []
    thread = threading.Thread(target=run_attack, args=args)
    thread.daemon = True
    thread.start()
    time.sleep(2)
    return "".join(run_output_lines) + "\n[攻击正在后台运行...]"

def get_run_output():
    return "".join(run_output_lines)

def stop_attack():
    global run_process
    if run_process:
        run_process.terminate()
        return "已停止运行"
    return "没有正在运行的进程"

# ==========================================
# 结果浏览
# ==========================================
def get_result_dirs():
    results_dir = AGENTLAB_DIR / "agentlab_results"
    if not results_dir.exists():
        return []
    dirs = sorted(results_dir.iterdir(), reverse=True)
    return [d.name for d in dirs if d.is_dir()]

def load_results(run_name):
    if not run_name:
        return "请选择运行记录", ""
    run_dir = AGENTLAB_DIR / "agentlab_results" / run_name
    lines = [f"### 运行记录: {run_name}\n"]

    config_file = run_dir / "config.json"
    if config_file.exists():
        config = load_json(config_file)
        lines.append("**配置:**")
        lines.append(f"```json\n{json.dumps(config, indent=2, ensure_ascii=False)}\n```\n")

    for subdir in run_dir.iterdir():
        if subdir.is_dir():
            lines.append(f"#### 受害模型: {subdir.name}\n")
            for f in subdir.iterdir():
                if f.suffix == ".json":
                    lines.append(f"**{f.name}**")
                    try:
                        data = load_json(f)
                        lines.append(f"```json\n{json.dumps(data, indent=2, ensure_ascii=False)[:3000]}\n```")
                    except:
                        lines.append(f"(文件大小: {f.stat().st_size} bytes)")
                    lines.append("")
                elif f.suffix == ".csv":
                    lines.append(f"**{f.name}** (CSV 文件)")
                    lines.append("")
                elif f.suffix == ".md":
                    lines.append(f"**{f.name}** (Markdown 报告)")
                    try:
                        lines.append(f"```markdown\n{f.read_text(encoding='utf-8')[:2000]}\n```")
                    except:
                        pass
                    lines.append("")

    return "\n".join(lines), run_name

# ==========================================
# 构建 UI
# ==========================================
def build_ui():
    with gr.Blocks(title="AgentLAB 可视化运行平台") as app:
        gr.Markdown("# 🛡️ AgentLAB 可视化运行平台")
        gr.Markdown("LLM Agent 长程攻击基准测试 — 浏览数据集、配置参数、运行攻击")
        gr.Markdown("> ⚠️ **注意**：每次运行前请填写 API Key，默认开启轻量模式，预算上限 **10 CNY**。拖动滑块可实时查看成本预估。")

        with gr.Tabs():
            # ==================== Tab 1: 数据集浏览 ====================
            with gr.Tab("📊 数据集浏览"):
                with gr.Row():
                    dataset_dd = gr.Dropdown(
                        choices=list(DATASETS.keys()),
                        label="选择数据集",
                        value=list(DATASETS.keys())[0] if DATASETS else None
                    )
                    refresh_btn = gr.Button("🔄 刷新", variant="secondary")

                with gr.Row():
                    with gr.Column(scale=1):
                        overview_md = gr.Markdown("选择数据集后显示统计信息")
                    with gr.Column(scale=2):
                        data_table = gr.Dataframe(
                            label="数据集样本列表",
                            interactive=False,
                            wrap=True
                        )

                with gr.Row():
                    sample_idx = gr.Number(label="样本索引", value=0, precision=0)
                    view_btn = gr.Button("📋 查看样本详情", variant="primary")

                sample_detail = gr.Markdown("点击「查看样本详情」显示完整 JSON")

                def refresh_datasets():
                    global DATASETS
                    DATASETS = get_datasets()
                    return gr.update(choices=list(DATASETS.keys()),
                                   value=list(DATASETS.keys())[0] if DATASETS else None)

                dataset_dd.change(get_dataset_overview, inputs=[dataset_dd],
                                outputs=[overview_md, data_table, sample_detail])
                refresh_btn.click(refresh_datasets, outputs=[dataset_dd])
                view_btn.click(get_sample_detail, inputs=[dataset_dd, sample_idx],
                             outputs=[sample_detail])

            # ==================== Tab 2: 环境工具浏览 ====================
            with gr.Tab("🔧 环境工具"):
                env_names = get_env_list()
                with gr.Row():
                    env_dd = gr.Dropdown(
                        choices=env_names,
                        label="选择环境",
                        value=env_names[0] if env_names else None
                    )

                env_info = gr.Markdown("选择环境后显示信息")
                env_table = gr.Dataframe(
                    label="工具列表",
                    interactive=False,
                    wrap=True
                )

                env_dd.change(get_env_detail, inputs=[env_dd],
                            outputs=[env_info, env_table])

            # ==================== Tab 3: 攻击运行 ====================
            with gr.Tab("⚡ 运行攻击"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("### 🔑 API 配置")
                        api_key = gr.Textbox(
                            label="API Key",
                            placeholder="sk-... 请手动输入，不会自动保存",
                            type="password",
                            value=""
                        )
                        base_url = gr.Textbox(
                            label="Base URL (OpenAI 兼容)",
                            value="https://api.deepseek.com",
                            placeholder="https://api.deepseek.com"
                        )

                        gr.Markdown("### ⚙️ 攻击脚本")
                        script = gr.Dropdown(
                            choices=["Intent-Hijacking.py", "Tool-chaining.py", "Memory-Poisoning.py"],
                            label="选择攻击脚本",
                            value="Intent-Hijacking.py"
                        )

                        gr.Markdown("### 🤖 模型配置")
                        victim_model = gr.Textbox(
                            label="受害模型 (Victim)",
                            value="deepseek-v4-pro"
                        )
                        attacker_url = gr.Textbox(
                            label="攻击者 API URL",
                            value="https://api.deepseek.com"
                        )
                        attacker_model = gr.Textbox(
                            label="攻击者模型",
                            value="deepseek-v4-pro"
                        )
                        planner_model = gr.Textbox(
                            label="Planner/Judge 模型",
                            value="deepseek-v4-pro"
                        )

                    with gr.Column(scale=1):
                        gr.Markdown("### 🎯 攻击参数")
                        num_samples = gr.Slider(
                            minimum=1, maximum=200, value=5, step=1,
                            label="样本数量 (推荐 ≤5)"
                        )
                        max_turns = gr.Slider(
                            minimum=1, maximum=20, value=3, step=1,
                            label="最大对话轮次 (推荐 ≤3, 每轮=3次API调用)"
                        )
                        num_strategies = gr.Slider(
                            minimum=1, maximum=5, value=1, step=1,
                            label="策略数量 (推荐 1)"
                        )
                        success_threshold = gr.Slider(
                            minimum=1, maximum=5, value=4, step=1,
                            label="成功阈值 (1-5)"
                        )
                        no_textgrad = gr.Checkbox(label="禁用 TextGrad", value=True)
                        sequential = gr.Checkbox(label="顺序执行 (非并行)", value=True)
                        lightweight_mode = gr.Checkbox(
                            label="⚡ 轻量模式 (max_turns=2, 样本≤3, 最快最省)",
                            value=True
                        )
                        cost_estimate = gr.Markdown(
                            "💰 **预估成本**: 样本×轮次×0.04 + 策略×0.02 ≈ **0.62 CNY**\n"
                            "  💳 预算上限: **10.00 CNY** — 当前设置安全"
                        )

                        with gr.Row():
                            validate_btn = gr.Button("🔍 配置验证 (1次调用~0.62元)", variant="secondary")
                            run_btn = gr.Button("🚀 开始攻击", variant="primary", size="lg")
                            stop_btn = gr.Button("⏹️ 停止", variant="stop")
                            poll_btn = gr.Button("📡 刷新输出", variant="secondary")

                gr.Markdown("### 📋 配置验证结果")
                validation_box = gr.Textbox(
                    label="验证结果（运行攻击前务必先验证）",
                    lines=8,
                    interactive=False,
                    placeholder="点击上方「配置验证」按钮，发送 1 次 API 调用验证配置是否正确。这会花费约 0.62 CNY，但能避免因配置错误浪费数百元。",
                )

                gr.Markdown("### 📜 运行输出")
                output_box = gr.Textbox(
                    label="控制台输出",
                    lines=25,
                    max_lines=50,
                    interactive=False,
                )

                run_args = [script, api_key, base_url, victim_model, attacker_url, attacker_model,
                           planner_model, num_samples, max_turns, num_strategies,
                           success_threshold, no_textgrad, sequential, lightweight_mode]

                # 成本预估更新函数
                def update_cost_estimate(n, t, s):
                    calls = n * t * 3 + s
                    cost = n * t * 0.04 + s * 0.02
                    safe = "✅ 安全" if cost <= 10 else "❌ 超预算"
                    return f"💰 **预估成本**: {n}×{t}×0.04 + {s}×0.02 ≈ **{cost:.2f} CNY**\n  💳 预算上限: **10.00 CNY** — {safe}"

                num_samples.change(update_cost_estimate, inputs=[num_samples, max_turns, num_strategies], outputs=[cost_estimate])
                max_turns.change(update_cost_estimate, inputs=[num_samples, max_turns, num_strategies], outputs=[cost_estimate])
                num_strategies.change(update_cost_estimate, inputs=[num_samples, max_turns, num_strategies], outputs=[cost_estimate])

                validate_btn.click(validate_config, inputs=[api_key, base_url, victim_model, attacker_url, planner_model], outputs=[validation_box])
                run_btn.click(run_attack_async, inputs=run_args, outputs=[output_box])
                stop_btn.click(stop_attack, outputs=[output_box])
                poll_btn.click(get_run_output, outputs=[output_box])

            # ==================== Tab 4: 结果查看 ====================
            with gr.Tab("📈 结果查看"):
                with gr.Row():
                    result_dd = gr.Dropdown(
                        choices=get_result_dirs(),
                        label="选择运行记录",
                        scale=3,
                    )
                    refresh_results_btn = gr.Button("🔄 刷新", variant="secondary", scale=1)
                    delete_btn = gr.Button("🗑️ 删除", variant="stop", scale=1)

                result_detail = gr.Markdown("选择运行记录后显示结果")
                delete_msg = gr.Markdown("")

                def refresh_results():
                    return gr.update(choices=get_result_dirs())

                def delete_result(run_name):
                    if not run_name:
                        return "⚠️ 请先选择要删除的运行记录", gr.update(choices=get_result_dirs())
                    run_dir = AGENTLAB_DIR / "agentlab_results" / run_name
                    if not run_dir.exists():
                        return f"⚠️ 记录 {run_name} 不存在", gr.update(choices=get_result_dirs())
                    import shutil
                    shutil.rmtree(run_dir)
                    return f"✅ 已删除: {run_name}", gr.update(choices=get_result_dirs())

                result_dd.change(load_results, inputs=[result_dd],
                               outputs=[result_detail, result_dd])
                refresh_results_btn.click(refresh_results, outputs=[result_dd])
                delete_btn.click(delete_result, inputs=[result_dd],
                               outputs=[delete_msg, result_dd])

            # ==================== Tab 5: 使用说明 ====================
            with gr.Tab("📖 使用说明"):
                gr.Markdown("""
## 📖 使用说明

### 1. 数据集浏览
- 在「数据集浏览」标签页中选择数据集
- 查看统计信息和样本列表
- 输入索引查看完整样本 JSON

### 2. 环境工具
- 浏览 AgentLAB 包含的 349 个环境
- 查看每个环境提供的工具和参数定义

### 3. 运行攻击
- **API 配置**: 输入你的 API Key 和 Base URL
  - DeepSeek: `https://api.deepseek.com`, 模型 `deepseek-v4-pro`
  - OpenAI: 默认 URL, 模型 `gpt-4o` / `gpt-5.1`
  - 本地 vLLM: `http://localhost:8000/v1`
- **选择脚本**: Intent-Hijacking / Tool-chaining / Memory-Poisoning
- **配置参数**: 样本数、轮次、策略数等
- **点击「开始攻击」**, 然后点击「刷新输出」查看实时输出

### 4. 结果查看
- 在「结果查看」标签页中选择历史运行记录
- 查看配置、攻击结果和统计报告

### 5. 五种攻击类型
| 攻击类型 | 脚本 | 说明 |
|---------|------|------|
| Intent Hijacking | `Intent-Hijacking.py` | 多轮社会工程攻击 |
| Tool Chaining | `Tool-chaining.py` | 恶意任务分解为良性工具调用 |
| Objective Drifting | `Objective-Drifting.py` | 环境观察逐步重定向目标 |
| Task Injection | `Task-Injection.sh` | 长程间接提示注入 |
| Memory Poisoning | `Memory-Poisoning.py` | 记忆中植入恶意偏好 |

### 6. 注意事项
- 运行 Intent Hijacking 需要 API 余额
- Tool Chaining 和 Objective Drifting 可能需要 vLLM (GPU)
- Task Injection 需要 conda 环境
- 如遇 402 错误,请检查 API 账户余额
""")

    return app

# ==========================================
# 启动
# ==========================================
if __name__ == "__main__":
    app = build_ui()
    app.launch(server_name="127.0.0.1", server_port=7860, share=False, inbrowser=True, theme=gr.themes.Soft())
