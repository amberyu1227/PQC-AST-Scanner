import os
from parser_cpp import get_cpp_parser
from scanner_base import BaseScanner  # 🚀 匯入基礎類別

# PQC 與傳統加密規則庫
CPP_PQC_RULES = {
    "EVP_sha1": "B303",
    "MD5_Init": "B324",
    "RSA_generate_key": "B413_RSA",
    "OQS_KEM_kyber_768_new": "B501_KYBER"
}

class CppScanner(BaseScanner):
    """
    C++ 專屬掃描器：繼承 BaseScanner，利用 Tree-sitter 進行結構化偵測
    """
    def __init__(self):
        # 初始化時先建立解析器，但不固定檔案路徑
        self.parser, self.language = get_cpp_parser()
        self.findings = []
        self.alias_map = {}

    def scan(self, filepath):
        """實作與 Python 版本對齊的 scan(filepath) 方法"""
        self.filename = filepath
        self.findings = []  # 清空前次掃描結果
        self.alias_map = {}

        if not os.path.exists(filepath):
            print(f"❌ 找不到檔案: {filepath}")
            return []

        with open(filepath, "rb") as f:
            code = f.read()

        tree = self.parser.parse(code)
        
        # 執行雙階段掃描
        self._collect_alias(tree.root_node)
        self._traverse(tree.root_node)
        
        return self.findings

    # ==============================
    # 🧠 結構化偵測核心邏輯
    # ==============================

    def _collect_alias(self, node):
        """收集 typedef 與 using 定義"""
        if node.type == "alias_declaration":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name and value:
                self.alias_map[name.text.decode()] = value.text.decode()
        
        if node.type == "type_definition":
            ids = [c for c in node.children if c.type in ["type_identifier", "primitive_type"]]
            if len(ids) >= 2:
                self.alias_map[ids[-1].text.decode()] = ids[-2].text.decode()

        for child in node.children:
            self._collect_alias(child)

    def _traverse(self, node):
        """遞迴走訪語法樹節點"""
        # 1. 偵測函式呼叫 (含 AES/ECC 參數檢查)
        if node.type == "call_expression":
            self._check_function_call(node)

        # 2. 硬編碼密鑰偵測 (初始化與賦值)
        if node.type in ["init_declarator", "assignment_expression"]:
            name_node = node.child_by_field_name("declarator") or node.child_by_field_name("left")
            value_node = node.child_by_field_name("value") or node.child_by_field_name("right")
            self._check_hardcoded_secret(name_node, value_node)

        # 3. 字串關鍵字掃描
        if node.type == "string_literal":
            self._check_string_keywords(node)

        for child in node.children:
            self._traverse(child)

    # ==============================
    # 🔍 細節檢查輔助方法
    # ==============================

    def _check_function_call(self, node):
        """檢查加密函式細節"""
        func_node = node.child_by_field_name("function")
        if not func_node: return
        
        func_name = self._extract_name(func_node)
        func_name = self.alias_map.get(func_name, func_name)
        if not func_name: return

        # AES ECB 模式檢查
        if "aes" in func_name.lower() and "ecb" in func_name.lower():
            self.report_finding(func_name, node.start_point[0] + 1, "B413_AES_WEAK")
            return

        # ECC 弱曲線檢查
        if "EC_KEY_new_by_curve_name" in func_name:
            curve = self._get_str_arg(node, 0)
            if curve and any(w in curve.upper() for w in ['SECP192', 'P-192', 'BRAINPOOLP160']):
                self.report_finding(f"{func_name}({curve})", node.start_point[0] + 1, "B415_ECC_WEAK_CURVE")
                return

        # RSA 與 PQC 基本匹配
        if func_name in CPP_PQC_RULES:
            rule_id = CPP_PQC_RULES[func_name]
            if func_name == "RSA_generate_key":
                bits = self._get_int_arg(node, 0)
                if bits and bits < 2048:
                    rule_id = "B413_RSA_WEAK_SIZE"
            self.report_finding(func_name, node.start_point[0] + 1, rule_id)

    def _check_hardcoded_secret(self, name_node, value_node):
        """偵測硬編碼秘密"""
        if not name_node or not value_node or value_node.type != "string_literal":
            return
            
        var_name = name_node.text.decode().lower()
        val = value_node.text.decode().strip('"')
        line = value_node.start_point[0] + 1
        
        if len(val) > 8:
            if val.startswith(("AKIA", "ASIA")):
                self.report_finding(var_name, line, "B707_HARDCODED_AWS")
            elif any(s in var_name for s in ['password', 'pwd']) and "hash" not in var_name:
                self.report_finding(var_name, line, "B706_HARDCODED_PASSWORD")
            elif ("sk" in var_name or "secret" in var_name) and ("pqc" in var_name or "kyber" in var_name):
                self.report_finding(var_name, line, "B709_HARDCODED_PQC_SK")
            elif any(s in var_name for s in ['key', 'secret']) and all(x not in var_name for x in ['public', 'pub']):
                self.report_finding(var_name, line, "B702_HARDCODED_KEY")

    def _check_string_keywords(self, node):
        """字串關鍵字掃描"""
        text = node.text.decode().upper()
        if "KYBER" in text or "ML-KEM" in text:
            self.report_finding(text, node.start_point[0] + 1, "B501_KYBER")
        elif "DILITHIUM" in text or "ML-DSA" in text:
            self.report_finding(text, node.start_point[0] + 1, "B502_DILITHIUM")

    # ==============================
    # 🧩 工具方法
    # ==============================

    def _get_int_arg(self, node, index):
        """提取整數參數"""
        arg_list = node.child_by_field_name("arguments")
        if not arg_list: return None
        actual = [c for c in arg_list.children if c.type not in ["(", ")", ","]]
        if len(actual) > index and actual[index].type == "number_literal":
            return int(actual[index].text.decode())
        return None

    def _get_str_arg(self, node, index):
        """提取字串參數"""
        arg_list = node.child_by_field_name("arguments")
        if not arg_list: return None
        actual = [c for c in arg_list.children if c.type not in ["(", ")", ","]]
        if len(actual) > index and actual[index].type == "string_literal":
            return actual[index].text.decode().strip('"')
        return None

    def _extract_name(self, node):
        """解析函式名稱"""
        if node.type == "identifier": return node.text.decode()
        if node.type == "field_expression":
            field = node.child_by_field_name("field")
            return field.text.decode() if field else None
        if node.type == "qualified_identifier":
            name = node.child_by_field_name("name")
            return name.text.decode() if name else None
        return None

    def report_finding(self, snippet, line, rule_id):
        from scanner_base import PQC_KNOWLEDGE_BASE
    
        # 取得基礎資訊
        rule_info = PQC_KNOWLEDGE_BASE.get(rule_id, {})
        
        self.findings.append({
            "RuleID": rule_id,
            "CodeSnippet": snippet,
            "Location": f"{self.filename}:{line}",
            "Type": rule_info.get("type", "Unknown"),
            "Message": rule_info.get("message", "N/A"),
            "FixSuggestion": rule_info.get("fix", "N/A")
        })

# --- 測試整合後的效果 ---
if __name__ == "__main__":
    test_target = "test_pqc.cpp"
    scanner = CppScanner()
    results = scanner.scan(test_target)  # 🚀 使用新的 scan(filepath) 介面
    
    print(f"\n--- [BaseScanner 整合版] 發現 {len(results)} 處風險 ---")
    for r in results:
        print(r)