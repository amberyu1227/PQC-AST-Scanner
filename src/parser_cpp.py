# parser_cpp.py
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

def get_cpp_parser():
    # 使用官方推薦的 Language 物件建立方式
    cpp_language = Language(tscpp.language())
    
    parser = Parser(cpp_language)
    
    return parser, cpp_language