import os
from parser_cpp import get_cpp_parser
from scanner_base import BaseScanner  # 🚀 匯入基礎類別

class CppScanner(BaseScanner):
    """
    C++ 專屬掃描器：繼承 BaseScanner，利用 Tree-sitter 進行結構化偵測
    """
    def __init__(self, filepath=None):
        # 初始化時先建立解析器，但不固定檔案路徑
        super().__init__(filepath)
        self.findings = []
        self.alias_map = {}
        self.parser, self.language = get_cpp_parser()

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
        # ─── 🚀 新增：AES 模式檢查 (區分 ECB 弱模式與 SAFE 安全資產) ───
        if "aes" in func_name.lower():
            if "ecb" in func_name.lower():
                self.report_finding(func_name, node.start_point[0] + 1, "B413_AES_WEAK")
            else:
                self.report_finding(func_name, node.start_point[0] + 1, "B413_AES_SAFE")
            return

        # ECC 弱曲線檢查
        if "EC_KEY_new_by_curve_name" in func_name:
            curve = self._get_str_arg(node, 0)
            if curve and any(w in curve.upper() for w in ['SECP192', 'P-192', 'BRAINPOOLP160']):
                self.report_finding(f"{func_name}({curve})", node.start_point[0] + 1, "B415_ECC_WEAK_CURVE")
                return

        # ─── 🚀 核心優化：完全連接 base 檔案，向父類別查詢通用 RuleID ───
        rule_id = self.get_rule_id("cpp", func_name)
        if rule_id:
            # 針對 RSA 生成進行長度二度判定
            if func_name == "RSA_generate_key":
                bits = self._get_int_arg(node, 0)
                if bits and bits < 2048:
                    rule_id = "B413_RSA_WEAK_SIZE"
            self.report_finding(func_name, node.start_point[0] + 1, rule_id)

        # ─── 🚀 關鍵新增：執行進階高級密碼學參數分析 (非正規表示式) ───
        self._check_advanced_crypto_rules(func_name, node)

    def _check_advanced_crypto_rules(self, func_name, node):
        """
        深度分析 OpenSSL / EVP 函式庫的參數，識別複雜密碼學風險
        """
        line = node.start_point[0] + 1

        # 【弱加密 DES/3DES】與【AES CBC/CFB IV 缺失】
        if func_name in ["EVP_EncryptInit_ex", "EVP_CipherInit_ex"]:
            cipher_arg = self._get_cipher_type_node(node, 1)
            if cipher_arg:
                cipher_name = cipher_arg.lower()
                
                # 1. 偵測 DES/3DES 弱加密演算法
                if "des" in cipher_name:
                    self.report_finding(func_name, line, "B304")
                    return
                
                # 2. 偵測 CBC/CFB 模式下的 IV 缺失 (IV 傳入 NULL 或 0)
                if any(mode in cipher_name for mode in ["cbc", "cfb"]):
                    iv_arg_node = self._get_argument_node(node, 4)
                    if iv_arg_node and iv_arg_node.text.decode() in ["NULL", "0", "nullptr"]:
                        self.report_finding(f"{func_name} ({cipher_name} with NULL IV)", line, "B413_IV_WEAK")

        # 3. 【GCM Nonce 長度檢查】 (必須固定為 12 bytes)
        if func_name == "EVP_CIPHER_CTX_ctrl":
            ctrl_type = self._get_argument_text(node, 1)
            if ctrl_type == "EVP_CTRL_AEAD_SET_IVLEN":
                nonce_len = self._get_int_arg(node, 2)
                if nonce_len and nonce_len != 12:
                    self.report_finding(f"GCM Nonce Length: {nonce_len} bytes", line, "B416_GCM_NONCE_LENGTH")

        # 4. 【弱亂數 (Weak RNG)】 (不應在密碼學環境使用 rand/srand)
        if func_name in ["rand", "srand"]:
            self.report_finding(func_name, line, "B701_WEAK_RNG")

        # 5. 【PBKDF2 迭代次數過低】 與 6. 【Salt 長度不足】
        if func_name in ["PKCS5_PBKDF2_HMAC", "PKCS5_PBKDF2_HMAC_SHA1"]:
            salt_len = self._get_int_arg(node, 3)
            iterations = self._get_int_arg(node, 4)

            # Salt 長度檢驗 (< 16 bytes 報警)
            if salt_len and salt_len < 16:
                self.report_finding(f"PBKDF2 Salt Length: {salt_len} bytes", line, "B710_SHORT_SALT")

            # 迭代次數檢驗 (< 600,000 次 報警)
            if iterations and iterations < 600000:
                self.report_finding(f"PBKDF2 Iterations: {iterations}", line, "B703_WEAK_KDF_ITERATIONS")

        # 7. 【ECC 整體資產識別】
        if func_name in ["EC_KEY_new", "EC_KEY_new_by_curve_name", "EC_GROUP_new_by_curve_name"]:
            self.report_finding(func_name, line, "B413_ECC")

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
            elif ("token" in var_name or "api_key" in var_name) and "csrf" not in var_name:
                self.report_finding(var_name, line, "B708_HARDCODED_TOKEN")
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

    def _get_argument_node(self, node, index):
        """根據索引獲取原始的參數節點"""
        arg_list = node.child_by_field_name("arguments")
        if not arg_list: return None
        actual = [c for c in arg_list.children if c.type not in ["(", ")", ","]]
        if len(actual) > index:
            return actual[index]
        return None

    def _get_argument_text(self, node, index):
        """獲取特定索引參數的文字"""
        arg_node = self._get_argument_node(node, index)
        return arg_node.text.decode() if arg_node else None

    def _get_cipher_type_node(self, node, index):
        """解析如 EVP_des_ecb() 這種巢狀函式呼叫的名稱"""
        arg_node = self._get_argument_node(node, index)
        if not arg_node: return None
        if arg_node.type == "call_expression":
            func_node = arg_node.child_by_field_name("function")
            if func_node: return func_node.text.decode()
        return arg_node.text.decode()

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
        """呼叫 BaseScanner 取得完整的風險資訊，並加入 findings 列表"""
        # 透過 super() 呼叫父類別的 report_finding
        # 父類別會自動去 PQC_KNOWLEDGE_BASE 查表，幫我們補齊 Type, Message, Fix 等欄位
        full_finding = super().report_finding(snippet, line, rule_id)
        
        # 將完整的字典存入掃描結果中
        self.findings.append(full_finding)

# --- 測試整合後的效果 ---
if __name__ == "__main__":
    import sys
    target_file = sys.argv[1]
    scanner = CppScanner()
    results = scanner.scan(target_file)  # 🚀 使用新的 scan(filepath) 介面
    
    print(f"\n--- [BaseScanner 整合版] 發現 {len(results)} 處風險 ---")
    for r in results:
        print(r)