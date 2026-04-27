from tree_sitter import Parser
from tree_sitter_languages import get_language

def get_cpp_parser():
    parser = Parser()

    cpp_language = get_language("cpp")  # ✅ 完全相容版本

    parser.set_language(cpp_language)

    return parser, cpp_language
