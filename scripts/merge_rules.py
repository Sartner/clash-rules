#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash规则文件合并工具
支持多组URL源，每组输出独立的配置文件
"""

import yaml
import requests
import argparse
import sys
import hashlib
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import time


class ConfigManager:
    """配置管理器 - 负责加载和验证YAML配置"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = {}

    def load_config(self) -> Dict:
        """加载YAML配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)

            # 验证配置
            if not self._validate_config():
                print("❌ 配置文件验证失败")
                return {}

            print(f"✅ 成功加载配置文件: {self.config_path}")
            return self.config
        except FileNotFoundError:
            print(f"❌ 配置文件不存在: {self.config_path}")
            return {}
        except yaml.YAMLError as e:
            print(f"❌ YAML解析错误: {e}")
            return {}
        except Exception as e:
            print(f"❌ 加载配置失败: {e}")
            return {}

    def _validate_config(self) -> bool:
        """验证配置格式"""
        if not self.config:
            print("❌ 配置为空")
            return False

        # 检查全局配置
        if 'global' not in self.config:
            self.config['global'] = {}
            print("⚠️  未找到全局配置，使用默认值")

        # 检查规则组
        if 'rule_groups' not in self.config:
            print("❌ 未找到 rule_groups 配置")
            return False

        if not isinstance(self.config['rule_groups'], list):
            print("❌ rule_groups 必须是列表")
            return False

        if not self.config['rule_groups']:
            print("❌ rule_groups 不能为空")
            return False

        # 验证每个规则组
        for i, group in enumerate(self.config['rule_groups']):
            if not self._validate_rule_group(group, i):
                return False

        return True

    def _validate_rule_group(self, group: Dict, index: int) -> bool:
        """验证规则组配置"""
        if not isinstance(group, dict):
            print(f"❌ 规则组 {index} 必须是字典")
            return False

        # 检查必需字段
        if 'name' not in group:
            print(f"❌ 规则组 {index} 缺少 name 字段")
            return False

        if 'output' not in group:
            print(f"❌ 规则组 {index} 缺少 output 字段")
            return False

        if 'sources' not in group:
            print(f"❌ 规则组 {index} 缺少 sources 字段")
            return False

        if not isinstance(group['sources'], list):
            print(f"❌ 规则组 {index} 的 sources 必须是列表")
            return False

        if not group['sources']:
            print(f"❌ 规则组 {index} 的 sources 不能为空")
            return False

        # 验证每个源
        for j, source in enumerate(group['sources']):
            if not isinstance(source, dict):
                print(f"❌ 规则组 {index} 的源 {j} 必须是字典")
                return False

            if 'url' not in source:
                print(f"❌ 规则组 {index} 的源 {j} 缺少 url 字段")
                return False

        return True

    def get_global_config(self) -> Dict:
        """获取全局配置"""
        return self.config.get('global', {})

    def get_rule_groups(self) -> List[Dict]:
        """获取规则组列表"""
        return self.config.get('rule_groups', [])


class RuleSource:
    """规则源 - 表示一个URL源"""

    def __init__(self, url: str, name: str = "", retries: int = 3, timeout: int = 60):
        self.url = url
        self.name = name or url
        self.retries = retries
        self.timeout = timeout
        self.data: Optional[Dict] = None
        self.raw_text: str = ""
        self.error: Optional[str] = None

    def download(self) -> bool:
        """
        下载规则文件
        返回: 是否成功
        """
        for attempt in range(self.retries):
            try:
                print(f"  📥 正在下载: {self.name}")
                print(f"      URL: {self.url}")
                print(f"      尝试 {attempt + 1}/{self.retries}")

                response = requests.get(self.url, timeout=self.timeout)
                response.raise_for_status()

                self.raw_text = response.text

                # 解析YAML
                try:
                    self.data = yaml.safe_load(self.raw_text)
                except yaml.YAMLError as e:
                    self.error = f"YAML解析失败: {e}"
                    print(f"  ❌ {self.error}")
                    continue

                if not self.data or 'payload' not in self.data:
                    self.error = "无效的规则文件格式"
                    print(f"  ❌ {self.error}")
                    continue

                print(f"  ✅ 下载成功: {len(self.data['payload'])} 条规则")
                return True

            except requests.RequestException as e:
                self.error = f"下载失败: {e}"
                print(f"  ❌ {self.error} (尝试 {attempt + 1}/{self.retries})")
                if attempt < self.retries - 1:
                    print("      等待2秒后重试...")
                    time.sleep(2)
            except Exception as e:
                self.error = f"未知错误: {e}"
                print(f"  ❌ {self.error}")
                break

        return False

    def extract_header(self) -> str:
        """提取源文件的注释头部"""
        if not self.raw_text:
            return ""

        lines = self.raw_text.split('\n')
        header_lines = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or stripped == '':
                header_lines.append(line)
            else:
                break

        return '\n'.join(header_lines)


class RuleGroup:
    """规则组 - 表示一组要合并的源"""

    def __init__(self, config: Dict, global_config: Dict):
        self.name = config['name']
        self.description = config.get('description', '')
        self.output_file = config['output']
        self.output_dir = global_config.get('output_dir', '')
        self.custom_header = config.get('header', [])
        self.deduplication = config.get('deduplication', global_config.get('deduplication', 'group'))
        self.sources = [
            RuleSource(
                source['url'],
                source.get('name', source['url']),
                global_config.get('retries', 3),
                global_config.get('timeout', 60)
            )
            for source in config['sources']
        ]
        self.stats = {
            'total_sources': len(self.sources),
            'successful_sources': 0,
            'failed_sources': 0,
            'total_rules': 0,
            'deduplicated_rules': 0,
            'removed_count': 0
        }

    def add_source(self, source: RuleSource):
        """添加规则源"""
        self.sources.append(source)

    def merge(self) -> Tuple[Dict, str]:
        """
        合并规则组中的所有源
        返回: (合并后的数据, 头部注释)
        """
        print(f"\n📦 开始处理规则组: {self.name}")
        print(f"   输出文件: {self.output_file}")
        print(f"   源数量: {len(self.sources)}")
        print(f"   去重策略: {self.deduplication}")

        # 下载所有源
        self._download_all_sources()

        # 提取数据
        all_payloads = []
        for source in self.sources:
            if source.data and 'payload' in source.data:
                all_payloads.append((source, source.data['payload']))

        if not all_payloads:
            print("❌ 没有有效的规则数据")
            return {"payload": [], "version": 1}, ""

        # 合并和去重
        merged_data, dedup_stats = self._merge_and_deduplicate(all_payloads)

        # 计算Payload的MD5值
        payload_md5 = self._calculate_payload_md5(merged_data['payload'])

        # 生成头部
        header = self._generate_header(dedup_stats, payload_md5)

        return merged_data, header

    def _download_all_sources(self):
        """下载所有源"""
        print("\n  📥 正在下载源...")

        for source in self.sources:
            if source.download():
                self.stats['successful_sources'] += 1
            else:
                self.stats['failed_sources'] += 1
                print(f"  ⚠️  源下载失败: {source.name}")

    def _merge_and_deduplicate(self, sources_data: List[Tuple[RuleSource, List]]) -> Tuple[Dict, Dict]:
        """合并和去重"""
        if self.deduplication == 'none':
            # 不去重
            all_rules = []
            for source, payload in sources_data:
                all_rules.append({
                    'name': source.name,
                    'rules': payload
                })

            total = sum(len(payload) for _, payload in sources_data)
            self.stats['total_rules'] = total
            self.stats['deduplicated_rules'] = total
            self.stats['removed_count'] = 0

            return {
                "payload": all_rules,
                "version": 1
            }, {'total': total, 'deduplicated': total, 'removed': 0}

        elif self.deduplication == 'group':
            # 组内去重
            print("\n  🔄 执行组内去重...")

            seen = set()
            unique_rules = []
            total = 0

            for source, payload in sources_data:
                for rule in payload:
                    total += 1
                    rule_str = str(rule).strip()
                    if rule_str and rule_str not in seen:
                        seen.add(rule_str)
                        unique_rules.append(rule)

            self.stats['total_rules'] = total
            self.stats['deduplicated_rules'] = len(unique_rules)
            self.stats['removed_count'] = total - len(unique_rules)

            return {
                "payload": unique_rules,
                "version": 1
            }, {'total': total, 'deduplicated': len(unique_rules), 'removed': total - len(unique_rules)}

        elif self.deduplication == 'all':
            # 全局去重（扩展用，当前等价于组内）
            return self._merge_and_deduplicate(sources_data)

        else:
            print(f"  ⚠️  未知去重策略: {self.deduplication}，使用组内去重")
            return self._merge_and_deduplicate(sources_data)

    def _generate_header(self, dedup_stats: Dict, payload_md5: str = "") -> str:
        """生成输出文件头部"""
        lines = []

        # 自定义头部
        if self.custom_header:
            lines.extend(self.custom_header)
        else:
            # 默认头部
            lines.append(f"# NAME: {self.name} (Merged)")
            if self.description:
                lines.append(f"# DESCRIPTION: {self.description}")

            lines.append("# AUTHOR: blackmatrix7 (merged by script)")
            lines.append("# REPO: https://github.com/blackmatrix7/ios_rule_script")

        # 时间戳
        lines.append(f"# UPDATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # MD5校验值
        if payload_md5:
            lines.append(f"# MD5 (Payload): {payload_md5}")

        # 源信息
        lines.append("")
        lines.append("# SOURCES:")
        for source in self.sources:
            if source.data:
                lines.append(f"#   - {source.name}: {source.url}")

        # 统计信息
        lines.append("")
        lines.append("# STATS:")
        lines.append(f"#   Total Sources: {self.stats['total_sources']}")
        lines.append(f"#   Successful: {self.stats['successful_sources']}")
        lines.append(f"#   Failed: {self.stats['failed_sources']}")
        lines.append(f"#   Total Rules: {dedup_stats['total']}")
        lines.append(f"#   Deduplicated: {dedup_stats['deduplicated']}")
        lines.append(f"#   Removed: {dedup_stats['removed']}")
        lines.append("")
        lines.append("---")
        lines.append("")

        return '\n'.join(lines)

    def _calculate_payload_md5(self, payload: List) -> str:
        """
        计算Payload列表的MD5值
        """
        try:
            # 将payload序列化为字符串
            payload_lines = []

            # 检查数据格式
            if payload and len(payload) > 0 and isinstance(payload[0], dict) and 'name' in payload[0]:
                # 分组格式：先按组名排序，再按规则排序
                for group in sorted(payload, key=lambda x: x.get('name', '')):
                    for rule in sorted(group.get('rules', []), key=str):
                        payload_lines.append(str(rule).strip())
            else:
                # 平面格式：直接排序
                for rule in sorted(payload, key=str):
                    payload_lines.append(str(rule).strip())

            # 过滤空行
            payload_lines = [line for line in payload_lines if line]

            # 计算MD5
            payload_text = '\n'.join(payload_lines)
            return hashlib.md5(payload_text.encode('utf-8')).hexdigest()
        except Exception as e:
            print(f"  ⚠️  MD5计算失败: {e}")
            return ""

    def save(self, data: Dict, header: str) -> bool:
        """保存合并后的文件"""
        try:
            # 构建完整的输出文件路径
            if self.output_dir:
                # 确保输出目录存在
                os.makedirs(self.output_dir, exist_ok=True)
                # 组合完整路径
                output_path = os.path.join(self.output_dir, os.path.basename(self.output_file))
            else:
                output_path = self.output_file

            # 如果输出文件包含目录路径，确保目录存在
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            print(f"\n  💾 正在保存到: {output_path}")

            with open(output_path, 'w', encoding='utf-8') as f:
                # 写入头部
                f.write(header)

                # 检查数据格式
                if data['payload'] and isinstance(data['payload'][0], dict) and 'name' in data['payload'][0]:
                    # 格式1: 分组格式
                    for group in data['payload']:
                        f.write(f"\n# === {group['name']} ===\n")
                        for rule in group['rules']:
                            f.write(f"- {rule}\n")
                else:
                    # 格式2: 平面格式
                    f.write("payload:\n")
                    for rule in data['payload']:
                        f.write(f"- {rule}\n")

                # 版本信息
                f.write(f"\nversion: {data['version']}\n")

            print(f"  ✅ 保存成功")
            return True

        except Exception as e:
            print(f"  ❌ 保存失败: {e}")
            return False


class RuleMerger:
    """规则合并器 - 主控制器"""

    def __init__(self, config_path: Optional[str] = None, output_dir: str = ''):
        self.config_path = config_path
        self.config_manager: Optional[ConfigManager] = None
        self.output_dir = output_dir

    async def process_all_groups(self):
        """处理所有规则组"""
        if self.config_path:
            # 使用配置文件
            self.config_manager = ConfigManager(self.config_path)
            config = self.config_manager.load_config()

            if not config:
                print("❌ 加载配置失败，程序退出")
                return 1

            # 合并输出目录：命令行参数优先
            global_config = self.config_manager.get_global_config()
            if self.output_dir:
                global_config['output_dir'] = self.output_dir

            rule_groups = self.config_manager.get_rule_groups()

            print(f"\n{'=' * 60}")
            print(f"📋 共找到 {len(rule_groups)} 个规则组")
            print(f"{'=' * 60}")

            success_count = 0
            fail_count = 0

            for i, group_config in enumerate(rule_groups, 1):
                print(f"\n{'=' * 60}")
                print(f"🔄 处理 [{i}/{len(rule_groups)}] {group_config['name']}")
                print(f"{'=' * 60}")

                try:
                    group = RuleGroup(group_config, global_config)
                    merged_data, header = group.merge()

                    if group.save(merged_data, header):
                        success_count += 1
                        print(f"\n✅ 规则组 [{i}/{len(rule_groups)}] 处理完成")
                    else:
                        fail_count += 1
                        print(f"\n❌ 规则组 [{i}/{len(rule_groups)}] 处理失败")

                except Exception as e:
                    fail_count += 1
                    print(f"\n❌ 规则组 [{i}/{len(rule_groups)}] 出现异常: {e}")

            print(f"\n{'=' * 60}")
            print(f"📊 处理完成!")
            print(f"   成功: {success_count} 个")
            print(f"   失败: {fail_count} 个")
            print(f"{'=' * 60}")

        else:
            # 兼容模式：使用默认配置
            print("⚠️  未指定配置文件，使用兼容模式")
            return self._run_compat_mode()

        return 0

    def _run_compat_mode(self) -> int:
        """兼容模式：使用原始脚本的配置"""
        print("\n" + "=" * 60)
        print("🔄 兼容模式 - 使用默认配置")
        print("=" * 60)

        # 原始URL
        OPENAI_URL = "https://gh-proxy.com/raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/OpenAI/OpenAI.yaml"
        GEMINI_URL = "https://gh-proxy.com/raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Gemini/Gemini.yaml"
        OUTPUT_FILE = "sartner-ai.yaml"

        # 使用原始流程
        source1 = RuleSource(OPENAI_URL, "OpenAI")
        source2 = RuleSource(GEMINI_URL, "Gemini")

        print("\n📥 正在下载源...")
        if not source1.download():
            print("❌ OpenAI 下载失败")
            return 1
        if not source2.download():
            print("❌ Gemini 下载失败")
            return 1

        # 合并
        print("\n🔄 正在合并规则...")
        seen = set()
        unique_rules = []
        total = 0

        for source in [source1, source2]:
            if source.data and 'payload' in source.data:
                for rule in source.data['payload']:
                    total += 1
                    rule_str = str(rule).strip()
                    if rule_str and rule_str not in seen:
                        seen.add(rule_str)
                        unique_rules.append(rule)

        # 头部
        header_lines = [
            "# NAME: OpenAI + Gemini (Merged)",
            "# AUTHOR: blackmatrix7 (merged by script)",
            f"# UPDATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# TOTAL: {len(unique_rules)}",
            "",
            ""
        ]
        header = '\n'.join(header_lines)

        # 保存
        print(f"\n💾 正在保存到: {OUTPUT_FILE}")
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write("payload:\n")

                for rule in unique_rules:
                    f.write(f"- {rule}\n")

                f.write(f"\nversion: 1\n")

            print(f"✅ 合并完成! 输出文件: {OUTPUT_FILE}")
            print(f"   规则总数: {len(unique_rules)}")
            return 0
        except Exception as e:
            print(f"❌ 保存失败: {e}")
            return 1


def create_quick_config(args) -> Optional[str]:
    """创建快速配置的临时配置文件"""
    if not args.url or not args.output:
        return None

    config = {
        'global': {
            'deduplication': 'group',
            'retries': 3,
            'timeout': 60
        },
        'rule_groups': [{
            'name': 'quick-group',
            'description': f'Quick merge of {len(args.url)} sources',
            'output': args.output,
            'sources': [{'url': url, 'name': url} for url in args.url]
        }]
    }

    temp_config = 'temp_quick_config.yaml'
    with open(temp_config, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return temp_config


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='Clash规则文件合并工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 使用配置文件
  python merge_rules.py --config config.yaml

  # 使用配置文件并指定输出目录
  python merge_rules.py --config config.yaml --output-dir ./output

  # 快速合并两个URL
  python merge_rules.py --url url1.yaml --url url2.yaml --output merged.yaml

  # 快速合并并指定输出目录
  python merge_rules.py --url url1.yaml --url url2.yaml --output merged.yaml --output-dir ./output

  # 兼容模式（使用默认配置）
  python merge_rules.py
        """
    )

    # 主配置
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='YAML配置文件路径'
    )

    # 快速配置
    parser.add_argument(
        '--url', '-u',
        action='append',
        help='规则文件URL（可指定多次）'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        help='输出文件名（配合--url使用）'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default='',
        help='输出目录（可选，所有文件将保存到此目录）'
    )

    # 其他选项
    parser.add_argument(
        '--dedup', '-d',
        type=str,
        choices=['group', 'all', 'none'],
        default='group',
        help='去重策略: group=组内, all=全局, none=不去重'
    )

    args = parser.parse_args()

    # 切换到脚本所在目录，确保路径正确解析
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"📂 工作目录: {os.getcwd()}")

    # 验证输出目录
    if args.output_dir:
        # 转换为绝对路径
        args.output_dir = os.path.abspath(args.output_dir)
        print(f"📁 输出目录: {args.output_dir}")

    # 如果配置文件路径以 scripts/ 开头，移除前缀
    if args.config and args.config.startswith('scripts/'):
        args.config = args.config[8:]  # 移除 'scripts/' 前缀
        print(f"📄 配置文件: {args.config}")

    # 检查参数
    if args.config and (args.url or args.output):
        print("❌ 不能同时使用 --config 和 --url/--output")
        return 1

    if (args.url and not args.output) or (args.output and not args.url):
        print("❌ 使用 --url 时必须指定 --output")
        return 1

    print("\n" + "=" * 60)
    print("🚀 Clash规则合并器")
    print("=" * 60)

    merger = RuleMerger()

    # 处理配置
    if args.config:
        # 使用配置文件
        merger = RuleMerger(config_path=args.config, output_dir=args.output_dir)
        import asyncio
        return asyncio.run(merger.process_all_groups())

    elif args.url:
        # 快速配置
        temp_config = create_quick_config(args)
        if temp_config:
            merger = RuleMerger(config_path=temp_config, output_dir=args.output_dir)
            import asyncio
            result = asyncio.run(merger.process_all_groups())

            # 清理临时文件
            try:
                os.remove(temp_config)
            except:
                pass

            return result
        return 1

    else:
        # 兼容模式
        return merger._run_compat_mode()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断操作")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ 程序异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
