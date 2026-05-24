import javalang
from scanner_base import BaseScanner

class JavaScanner(BaseScanner):
    """
    Java 專屬掃描器：利用 javalang 解析 Java 源代碼，
    偵測弱加密實例、硬編碼金鑰、以及 PQC 遷移資產。
    """

    def is_secret_var(self, name):
        """ 判斷變數名稱是否敏感 (完整移植) """
        sensitive = ['key', 'secret', 'password', 'passwd', 'pwd', 'token', 'private', 'credential']
        name = name.lower()
        return any(k in name for k in sensitive) and "public" not in name and "hash" not in name

    def scan(self, filepath):
        """ 實作基類的 scan 方法 """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()

            # 1. 使用 javalang 解析器
            tree = javalang.parse.parse(code) 
            
        except javalang.tokenizer.LexerError as e:
            print(f"❌ Java Lexer Error ({filepath}): {e}")
            return []
        except javalang.parser.ParserError as e:
            print(f"❌ Java Parser Error ({filepath}): {e}")
            return []
        except Exception as e:
            print(f"❌ Java AST 錯誤 ({filepath}): {e}")
            return []

        # --- 2. 成功解析後，開始遍歷 AST ---
        for path, node in tree:
            try:
                if not isinstance(node, javalang.tree.Node):
                    continue
            except ValueError:
                continue
            
            # 行號處理邏輯 (完整移植你的路徑回溯修正)
            line_num = node.position.line if node.position else 0
            # 1. 如果行號為 0，且是方法呼叫 (如 getInstance)，嘗試從參數獲取行號
            if line_num == 0 and isinstance(node, javalang.tree.MethodInvocation):
                if node.arguments:
                    for arg in node.arguments:
                        if hasattr(arg, 'position') and arg.position:
                            line_num = arg.position.line
                            break
            # 2. 如果還是 0，則嘗試原本的「路徑回溯」邏輯
            if line_num == 0:
                try:
                    for p_item in reversed(path):
                        # 確保處理 javalang path 的 (attr, node) 結構
                        p_node = p_item[1] if isinstance(p_item, (list, tuple)) and len(p_item) == 2 else p_item
                        if hasattr(p_node, 'position') and p_node.position:
                            line_num = p_node.position.line
                            break
                except Exception:
                    pass
            # 排除頂層聲明
            if line_num == 0 and isinstance(node, (javalang.tree.PackageDeclaration, javalang.tree.Import)):
                continue

            # --- 3. 核心偵測邏輯 ---

            # [1] 方法呼叫檢查 (MethodInvocation)
            if isinstance(node, javalang.tree.MethodInvocation):
                if node.member == 'getInstance':
                    if node.arguments and isinstance(node.arguments[0], javalang.tree.Literal):
                        arg_value = node.arguments[0].value.strip('"').upper()
                        qualifier = node.qualifier if node.qualifier else "Cipher/Digest"
                        readable_snippet = f"{qualifier}.getInstance(\"{node.arguments[0].value.strip('\"')}\")"
                        
                        if "SHA1" in arg_value or "SHA-1" in arg_value:
                            self.findings.append(self.report_finding(readable_snippet, line_num, "B303"))
                        elif "MD5" in arg_value:
                            self.findings.append(self.report_finding(readable_snippet, line_num, "B324"))
                        elif "DES" in arg_value or "DESEDE" in arg_value:
                            self.findings.append(self.report_finding(readable_snippet, line_num, "B304")) 
                        elif "AES" in arg_value:
                            rule = "B413_AES_WEAK" if "ECB" in arg_value else "B413_AES_SAFE"
                            self.findings.append(self.report_finding(readable_snippet, line_num, rule))
                        elif "RSA" in arg_value:
                            self.findings.append(self.report_finding(readable_snippet, line_num, "B413_RSA"))
                        elif any(k in arg_value for k in ["EC", "ECDSA", "ECDH"]):
                            self.findings.append(self.report_finding(readable_snippet, line_num, "B413_ECC"))

                elif node.member == 'initialize':
                    if len(node.arguments) == 1 and isinstance(node.arguments[0], javalang.tree.Literal):
                        try:
                            key_size = int(node.arguments[0].value)
                            readable_snippet = f"keyPairGenerator.initialize({key_size})" 
                            if key_size < 2048:
                                self.findings.append(self.report_finding(readable_snippet, line_num, "B413_RSA_WEAK_SIZE", f"RSA 金鑰過短 ({key_size})"))
                            else:
                                self.findings.append(self.report_finding(readable_snippet, line_num, "B413_RSA", "RSA 金鑰生成 (PQC 目標)"))
                        except ValueError: pass
                
                elif node.member in ['nextInt', 'nextBytes']:
                    if hasattr(node, 'qualifier') and node.qualifier and 'rand' in node.qualifier.lower() and 'secure' not in node.qualifier.lower():
                        readable_snippet = f"{node.qualifier}.{node.member}(...)"
                        self.findings.append(self.report_finding(readable_snippet, line_num, "B701_WEAK_RNG"))
                
                elif node.member == 'init':
                    # 檢查 Cipher.init 是否漏傳 IV Parameter
                    # 寫法 1：cipher.init(Cipher.ENCRYPT_MODE, key) -> 只有 2 個參數
                    # 寫法 2：cipher.init(Cipher.ENCRYPT_MODE, key, null) -> 第 3 個參數傳 null
                    qualifier = node.qualifier.lower() if node.qualifier else ""
                    
                    # 過濾：確認這是一個加密器物件 (常見命名如 cipher, c, enc, dec 等)
                    if any(k in qualifier for k in ['cipher', 'cph', 'enc', 'dec']):
                        is_missing_iv = False
                        
                        if len(node.arguments) == 2:
                            is_missing_iv = True
                        elif len(node.arguments) >= 3:
                            arg3 = node.arguments[2]
                            if isinstance(arg3, javalang.tree.Literal) and arg3.value == 'null':
                                is_missing_iv = True
                                
                        if is_missing_iv:
                            qualifier_name = node.qualifier if node.qualifier else "Cipher"
                            readable_snippet = f"{qualifier_name}.init(..., /* Missing IV */)"
                            self.findings.append(self.report_finding(readable_snippet, line_num, "B413_IV_WEAK"))

            # [2] 變數宣告檢查 (LocalVariableDeclaration)
            elif isinstance(node, javalang.tree.LocalVariableDeclaration):
                for declarator in node.declarators:
                    var_name = declarator.name.lower()
                    if declarator.initializer and isinstance(declarator.initializer, javalang.tree.Literal):
                        raw_value = str(declarator.initializer.value)
                        if raw_value.startswith('"'):
                            value = raw_value.strip('"')
                            readable_snippet = f"{declarator.name} = \"{value[:15]}...\""
                            
                            if value.startswith(("AKIA", "ASIA")):
                                self.findings.append(self.report_finding(readable_snippet, line_num, "B707_HARDCODED_AWS"))
                            elif self.is_secret_var(var_name):
                                if "password" in var_name:
                                    self.findings.append(self.report_finding(readable_snippet, line_num, "B706_HARDCODED_PASSWORD"))
                                elif "token" in var_name:
                                    self.findings.append(self.report_finding(readable_snippet, line_num, "B708_HARDCODED_TOKEN"))
                                elif any(k in var_name for k in ["pqc", "kyber"]):
                                    self.findings.append(self.report_finding(readable_snippet, line_num, "B709_HARDCODED_PQC_SK"))
                                else:
                                    self.findings.append(self.report_finding(readable_snippet, line_num, "B702_HARDCODED_KEY"))
                    
                    if 'salt' in var_name and declarator.initializer:
                        init = declarator.initializer
                        salt_size = None
                        if isinstance(init, javalang.tree.ArrayCreator) and init.dimensions and init.dimensions[0].value.isdigit():
                            salt_size = int(init.dimensions[0].value)
                        elif isinstance(init, javalang.tree.ArrayInitializer) and init.initializers:
                            salt_size = len(init.initializers)
                        
                        if salt_size is not None and salt_size < 16:
                            self.findings.append(self.report_finding(f"byte[] {declarator.name}", line_num, "B710_SHORT_SALT"))

            # [3] 類別創建檢查 (ClassCreator)
            elif isinstance(node, javalang.tree.ClassCreator):
                type_name = node.type.name
                if type_name == 'Random':
                     self.findings.append(self.report_finding("new Random()", line_num, "B701_WEAK_RNG"))
                elif "PBEKeySpec" in type_name and len(node.arguments) >= 3:
                    iter_arg = node.arguments[2]
                    if isinstance(iter_arg, javalang.tree.Literal) and iter_arg.value.isdigit():
                        iterations = int(iter_arg.value)
                        if iterations < 600000:
                            self.findings.append(self.report_finding(f"new {type_name}(..., {iterations}, ...)", line_num, "B703_WEAK_KDF_ITERATIONS"))
                elif "ECGenParameterSpec" in type_name and len(node.arguments) > 0:
                    curve_arg = node.arguments[0]
                    if isinstance(curve_arg, javalang.tree.Literal):
                        curve_name = curve_arg.value.strip('"').upper()
                        if any(w in curve_name for w in ['SECP192', 'SECT163', 'BRAINPOOLP160']):
                            self.findings.append(self.report_finding(f"new {type_name}(\"{curve_name}\")", line_num, "B415_ECC_WEAK_CURVE"))
                elif "GCMParameterSpec" in type_name and len(node.arguments) >= 2:
                    iv_arg = node.arguments[1]
                    if isinstance(iv_arg, javalang.tree.ArrayCreator):
                        for dim in iv_arg.dimensions:
                            if isinstance(dim, javalang.tree.Literal) and dim.value.isdigit():
                                if int(dim.value) != 12:
                                    self.findings.append(self.report_finding("new GCMParameterSpec(...)", line_num, "B416_GCM_NONCE_LENGTH"))
            
            # [4] 字串常數檢查 (PQC 識別)
            elif isinstance(node, javalang.tree.Literal):
                val = str(node.value)
                if val.startswith('"'):
                    val_clean = val.strip('"').upper()
                    if any(k in val_clean for k in ["KYBER", "ML-KEM"]):
                        self.findings.append(self.report_finding(f"\"{val_clean}\"", line_num, "B501_KYBER"))
                    elif any(k in val_clean for k in ["DILITHIUM", "ML-DSA"]):
                        self.findings.append(self.report_finding(f"\"{val_clean}\"", line_num, "B502_DILITHIUM"))

        return self.findings