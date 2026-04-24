import ast
from scanner_base import BaseScanner

class PythonScanner(BaseScanner):
    """
    Python 專屬掃描器：利用 AST 遍歷 Python 源代碼，
    偵測弱加密演算法、硬編碼金鑰及 PQC 遷移目標。
    """

    def scan(self, filepath):
        """實作基類的 scan 方法"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # 解析 AST
            tree = ast.parse(code, filename=filepath)
            
            # 建立 Visitor 並執行遍歷
            # 將 self (PythonScanner 實例) 傳入，以便 Visitor 呼叫 report_finding
            visitor = self.PQC_AST_Visitor(self)
            visitor.visit(tree)
            
        except Exception as e:
            print(f"❌ Python AST 解析錯誤 ({filepath}): {e}")
            
        return self.findings

    class PQC_AST_Visitor(ast.NodeVisitor):
        def __init__(self, outer):
            self.outer = outer  # 指向 PythonScanner 實例

        # --- 輔助函式 (由原本邏輯遷移) ---
        def _get_literal_value(self, node):
            if isinstance(node, ast.Constant): return node.value
            return None

        def _get_call_arg_value(self, node, arg_index, kw_name):
            val = None
            for k in node.keywords:
                if k.arg == kw_name and isinstance(k.value, ast.Constant): 
                    val = k.value.value
            if val is None and len(node.args) > arg_index:
                if isinstance(node.args[arg_index], ast.Constant): 
                    val = node.args[arg_index].value
            return val

        def _get_full_name(self, node):
            if isinstance(node, ast.Attribute):
                return self._get_full_name(node.value) + "." + node.attr
            elif isinstance(node, ast.Name):
                return node.id
            return ""

        def _is_ecb_mode(self, call_node):
            for keyword in call_node.keywords:
                if keyword.arg == 'mode':
                    return 'ECB' in ast.unparse(keyword.value).upper()
            if len(call_node.args) > 1:
                return 'ECB' in ast.unparse(call_node.args[1]).upper()
            return False

        def _is_cbc_cfb_mode(self, call_node):
            for keyword in call_node.keywords:
                if keyword.arg == 'mode':
                    mode = ast.unparse(keyword.value).upper()
                    return 'CBC' in mode or 'CFB' in mode
            if len(call_node.args) > 1:
                mode = ast.unparse(call_node.args[1]).upper()
                return 'CBC' in mode or 'CFB' in mode
            return False

        def _has_keyword_arg(self, keywords, arg_name):
            return any(keyword.arg == arg_name for keyword in keywords)

        def _get_int_arg(self, args, index):
            if len(args) > index:
                arg = args[index]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                    return arg.value
            return None

        # --- 核心遍歷邏輯 (完整移植) ---

        def visit_Assign(self, node):
            target_name = ""
            for target in node.targets:
                if isinstance(target, ast.Name):
                    target_name = target.id.lower()
                    break
            
            if not target_name:
                self.generic_visit(node)
                return

            raw_value = self._get_literal_value(node.value)
            assigned_value = None 
            if isinstance(raw_value, str): 
                assigned_value = raw_value
            elif isinstance(raw_value, bytes):
                try: assigned_value = raw_value.decode('utf-8')
                except: assigned_value = str(raw_value)

            # 硬編碼檢查邏輯
            if assigned_value and len(assigned_value) > 8: 
                if assigned_value.startswith(("AKIA", "ASIA")):
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B707_HARDCODED_AWS"))
                elif any(s in target_name for s in ['password', 'passwd', 'pwd']) and "hash" not in target_name:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B706_HARDCODED_PASSWORD"))
                elif ("token" in target_name or "api_key" in target_name) and "csrf" not in target_name and len(assigned_value) > 10:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B708_HARDCODED_TOKEN"))
                elif ("sk" in target_name or "secret_key" in target_name) and ("pqc" in target_name or "kyber" in target_name):
                     self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B709_HARDCODED_PQC_SK"))
                elif any(s in target_name for s in ['key', 'secret', 'private']):
                    if "public" not in target_name and "pub" not in target_name:
                        self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B702_HARDCODED_KEY"))
            
            self.generic_visit(node)

        def visit_Call(self, node):
            full_name = self._get_full_name(node.func)
            
            # 1. 弱雜湊
            if "hashlib.sha1" in full_name:
                self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B303"))
            elif "hashlib.md5" in full_name: 
                self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B324"))
            elif "random.random" in full_name or "random.randint" in full_name:
                self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B701_WEAK_RNG"))   

            # 2. 量子脆弱/弱加密
            elif any(x in full_name for x in ["DES.new", "DES3.new", "Crypto.Cipher.DES"]):
                self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B304"))
            elif "RSA.generate" in full_name:
                key_size = self._get_int_arg(node.args, 0)
                rule = "B413_RSA_WEAK_SIZE" if key_size and key_size < 2048 else "B413_RSA"
                self.outer.findings.append(self.outer.report_finding(node, node.lineno, rule))
                 
            # 3. AES 模式與 Nonce 檢查
            elif "AES.new" in full_name:
                is_ecb = self._is_ecb_mode(node)
                is_cbc_cfb = self._is_cbc_cfb_mode(node)
                iv_is_missing = not self._has_keyword_arg(node.keywords, 'iv')
                
                if is_ecb: 
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B413_AES_WEAK")) 
                elif is_cbc_cfb and iv_is_missing: 
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B413_IV_WEAK")) 
                else:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B413_AES_SAFE")) 

                # GCM Nonce 長度檢查
                is_gcm = any(k.arg == 'mode' and 'GCM' in ast.unparse(k.value).upper() for k in node.keywords)
                if is_gcm:
                    for k in node.keywords:
                        if k.arg == 'nonce' and isinstance(k.value, ast.Call) and "urandom" in ast.unparse(k.value.func):
                            nonce_size = self._get_int_arg(k.value.args, 0)
                            if nonce_size is not None and nonce_size != 12:
                                self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B416_GCM_NONCE_LENGTH"))

            # PQC 關鍵字參數偵測 (Kyber, Dilithium)
            if node.args or node.keywords:
                try:
                    args_str = ", ".join([ast.unparse(a) for a in node.args])
                    args_str += ", ".join([ast.unparse(k.value) for k in node.keywords])
                    args_str = args_str.upper()
                    if "KYBER" in args_str or "ML-KEM" in args_str:
                        self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B501_KYBER"))
                    elif "DILITHIUM" in args_str or "ML-DSA" in args_str:
                        self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B502_DILITHIUM")) 
                except: pass

            # 密鑰派生檢查
            if "PBKDF2" in full_name:
                iters = self._get_call_arg_value(node, 3, 'iterations')
                if iters and isinstance(iters, int) and iters < 600000:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B703_WEAK_KDF_ITERATIONS"))
            
            # ECC 曲線偵測
            if ("generate_private_key" in full_name and "ec" in full_name) or "ECC.generate" in full_name:
                is_weak = False
                for k in node.keywords:
                    if k.arg == 'curve':
                        val = ast.unparse(k.value).upper()
                        if any(w in val for w in ['SECP192', 'SECT163', 'P-192', 'BRAINPOOLP160']):
                            self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B415_ECC_WEAK_CURVE"))
                            is_weak = True
                if not is_weak and "ECC.generate" in full_name:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B413_ECC"))

            # Salt 長度檢查
            if "os.urandom" in full_name:
                size = self._get_int_arg(node.args, 0)
                if size is not None and size < 16 and size != 12:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B710_SHORT_SALT"))

            self.generic_visit(node)

        def visit_Constant(self, node):
            if isinstance(node.value, str):
                val = node.value.upper()
                if "KYBER" in val or "ML-KEM" in val:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B501_KYBER"))
                elif "DILITHIUM" in val or "ML-DSA" in val:
                    self.outer.findings.append(self.outer.report_finding(node, node.lineno, "B502_DILITHIUM"))
            self.generic_visit(node)