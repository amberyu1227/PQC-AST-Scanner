from tree_sitter import Language, Parser
import tree_sitter_cpp  # 🚀 強制寫明官方套件，絕不讓 VS Code 亂改

def get_cpp_parser():
    """
    使用官方原生 tree-sitter-cpp 載入 C++ 語法解析器
    完全相容新舊版 tree-sitter-cpp 的屬性異動 (涵蓋 LANGUAGE 與 language())
    """
    # 1. 取得語言物件 (自動偵測當前安裝的版本 API)
    if hasattr(tree_sitter_cpp, "LANGUAGE"):
        # 最新版 API (0.22.0 以上版本)
        cpp_lang_obj = tree_sitter_cpp.LANGUAGE
    elif hasattr(tree_sitter_cpp, "language"):
        # 舊版與過渡版 API
        try:
            cpp_lang_obj = tree_sitter_cpp.language()
        except TypeError:
            cpp_lang_obj = tree_sitter_cpp.language
    else:
        raise RuntimeError("無法識別 tree_sitter_cpp 的語言屬性，請確認安裝狀態。")

    # 2. 封裝成 tree_sitter 核心可識別的 Language 物件
    try:
        cpp_language = Language(cpp_lang_obj)
    except Exception:
        # 若當前版本的 tree-sitter 核心不需 (或不允許) 二次封裝
        cpp_language = cpp_lang_obj
        
    # 3. 初始化解析器 (兼容新舊版 Parser 寫法)
    try:
        # 新版 (0.22.0+) 寫法：直接將語言傳入 Parser
        parser = Parser(cpp_language)
    except TypeError:
        # 舊版寫法：先建立 Parser 再 set_language
        parser = Parser()
        parser.set_language(cpp_language)
    
    return parser, cpp_language