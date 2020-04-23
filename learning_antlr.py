import re

from antlr4 import CommonTokenStream, FileStream, ParserRuleContext

from antlr_stuff.compiled.ANTLRv4Parser import ANTLRv4Parser
from antlr_stuff.compiled.ANTLRv4Lexer import ANTLRv4Lexer

antlr_parser = ANTLRv4Parser(CommonTokenStream(ANTLRv4Lexer(FileStream('JSON.g4', encoding='utf-8'))))
current_root = antlr_parser.grammarSpec()
# print(current_root)
# print(current_root.rules().ruleSpec())

# node = current_root

# for rule in node.rules().ruleSpec():
# 	print(type(rule).__name__)
# 	if rule.parserRuleSpec():
# 		rule_spec = rule.parserRuleSpec()
# 		print('parser', rule, str(rule_spec.RULE_REF()))
# 	elif rule.lexerRuleSpec():
# 		rule_spec = rule.lexerRuleSpec()
# 		print('lexer', rule, str(rule_spec.TOKEN_REF()))
# 	else:
# 		print('GAAAH')

escaped_values = {
	'n': '\n',
	'r': '\r',
	'b': '\b',
	't': '\t',
	'f': '\f',
	'\\': '\\',
	'-': '-',
	']': ']'
}

maximum_unicode_codepoint = 0x10FFFF

# Adapted from https://github.com/antlr/antlr4/blob/8c50731894e045be3e19799b84b39e9a60e2ab61/tool/src/org/antlr/v4/misc/EscapeSequenceParsing.java#L83
def parse_escape(s, start_offset):
	# Original Java code has to handle unicode codepoints which consist of more than one character,
	# however in Python 3.3+, we don't have to worry about this: https://stackoverflow.com/a/42262842

	offset = start_offset

	if offset + 2 > len(s) or s[offset] != '\\':
		# Invalid escape
		# TODO: Throw exception
		return None

	offset += 1 # Move past backslash
	escaped = s[offset]
	offset += 1 # Move past escaped character

	if escaped == 'u':
		if offset + 3 > len(s):
			# \u{1} is the shortest we support
			# TODO: Throw exception
			return None

		hex_start_offset = None
		hex_end_offset = None # Exclusive

		if s[offset] == '{':
			hex_start_offset = offset + 1

			try:
				hex_end_offset = s.index('}', hex_start_offset)
			except ValueError:
				# Closing bracket not found
				# TODO: Throw exception
				return None

			offset = hex_end_offset + 1
		else:
			if offset + 4 > len(s):
				# \uXXXX
				# TODO: Throw exception
				return None

			hex_start_offset = offset
			hex_end_offset = hex_start_offset + 4
			offset = hex_end_offset

		try:
			unicode_codepoint = int(s[hex_start_offset:hex_end_offset], 16)
		except ValueError:
			# Invalid hex
			# TODO: Throw exception
			return None

		if unicode_codepoint < 0 or unicode_codepoint > maximum_unicode_codepoint:
			# Invalid unicode
			# TODO: Throw exception
			return None

		return (unicode_codepoint, offset)
	elif escaped == 'p' or escaped == 'P':
		# Not supported (yet)
		# TODO: Throw exception
		return None
	elif escaped in escaped_values:
		return (ord(escaped_values[escaped]), offset)
	else:
		# TODO: Throw exception
		return None


# https://unicode-org.github.io/icu-docs/apidoc/released/icu4j/com/ibm/icu/text/UnicodeSet.html
# https://github.com/antlr/antlr4/blob/8c50731894e045be3e19799b84b39e9a60e2ab61/tool/src/org/antlr/v4/automata/LexerATNFactory.java#L439
# https://github.com/antlr/antlr4/blob/master/tool/src/org/antlr/v4/misc/EscapeSequenceParsing.java
# Unicode codepoint is one character, in Python 3.3+: https://stackoverflow.com/a/42262842
def charset_split(src):
	ranges = []

	start = 0
	for end in range(1, len(src) + 1):
		subset = src[start:end]

		if len(subset) == 1 and subset != '\\':
			ranges.append((ord(subset), ord(subset) + 1))
			start += 1
		elif len(subset) == 2



def lexer_charset_interval(src):
	elements = re.split(r'(\w-\w)', src) # Bug in this handling: ["\\\u0000-\u001F]
	ranges = []
	for element in elements:
		if not element:
			continue

		# Convert character sequences like \n, \t, etc. into a single character.
		element = bytes(element, 'utf-8').decode('unicode_escape') # Bug here too: [+\-]
		print(element)
		if len(element) > 1:
			if element[1] == '-' and len(element) == 3:
				ranges.append((ord(element[0]), ord(element[2]) + 1))
			else:
				for char in element:
					ranges.append((ord(char), ord(char) + 1))
		elif len(element) == 1:
			ranges.append((ord(element), ord(element) + 1))
	return ranges

def process_charset(src):
	return lexer_charset_interval(src[1:-1])

class Node():
	def __init__(self):
		self.children = []

	def add_child(self, child):
		self.children.append(child)

class ParserRuleNode(Node):
	def __init__(self, name):
		super().__init__()
		print('ParserRuleNode', name)
		self.name = name

class LexerRuleNode(Node):
	def __init__(self, name):
		super().__init__()
		print('LexerRuleNode', name)
		self.name = name

class RuleRefNode(Node):
	def __init__(self, rule):
		super().__init__()
		print('RuleRefNode', rule)
		self.rule = rule

class TokenRefNode(Node):
	def __init__(self, token):
		super().__init__()
		print('TokenRefNode', token)
		self.token = token

class QuantifierNode(Node):
	def __init__(self, quant):
		super().__init__()
		print('QuantifierNode', quant)
		self.quant = quant

class AlternativeNode(Node):
	def __init__(self, label):
		super().__init__()
		print('AlternativeNode', label)
		self.label = label

class StringLiteralNode(Node):
	def __init__(self, value):
		super().__init__()
		print('StringLiteralNode', value)
		self.value = value

class CharsetNode(Node):
	def __init__(self, charset):
		super().__init__()
		print('CharsetNode', charset)
		self.charset = charset

class NotNode(Node):
	def __init__(self):
		super().__init__()
		print('Not')

def add_children(rule, node):
	if rule.getChildCount():
		for child in rule.children:
			build_graph(child, node)

def build_graph(rule, parent):
	if isinstance(rule, ANTLRv4Parser.ParserRuleSpecContext):
		node = ParserRuleNode(str(rule.RULE_REF()))
		parent.add_child(node)
		add_children(rule, node)

	elif isinstance(rule, ANTLRv4Parser.LexerRuleSpecContext):
		node = LexerRuleNode(str(rule.TOKEN_REF()))
		parent.add_child(node)
		add_children(rule, node)

	elif isinstance(rule, (ANTLRv4Parser.ElementContext, ANTLRv4Parser.LexerElementContext)):
		suffix = None
		if rule.ebnfSuffix():
			suffix = rule.ebnfSuffix()
		elif hasattr(rule, 'ebnf') and rule.ebnf() and rule.ebnf().blockSuffix():
			suffix = rule.ebnf().blockSuffix().ebnfSuffix()

		if suffix:
			node = QuantifierNode(suffix.children[0])
			parent.add_child(node)
			add_children(rule, node)
		else:
			build_graph(rule.children[0], parent)

	elif isinstance(rule, ANTLRv4Parser.RulerefContext):
		node = RuleRefNode(str(rule.RULE_REF()))
		parent.add_child(node)

	elif isinstance(rule, ANTLRv4Parser.TerminalContext):
		if rule.TOKEN_REF():
			node = TokenRefNode(str(rule.TOKEN_REF()))
			parent.add_child(node)
		elif rule.STRING_LITERAL():
			node = StringLiteralNode(str(rule.STRING_LITERAL()))
			parent.add_child(node)

	elif isinstance(rule, ANTLRv4Parser.LabeledAltContext):
		label = None
		if rule.identifier() and (rule.identifier().TOKEN_REF() or rule.identifier().RULE_REF()):
			label = str(rule.identifier().TOKEN_REF() or rule.identifier().RULE_REF())

		node = AlternativeNode(label)
		parent.add_child(node)
		add_children(rule.alternative(), node)

	elif isinstance(rule, (ANTLRv4Parser.AtomContext, ANTLRv4Parser.LexerAtomContext)):
		lexer_atom = isinstance(rule, ANTLRv4Parser.LexerAtomContext)

		if rule.DOT():
			print('DOT')
		elif rule.notSet():
			node = NotNode()
			parent.add_child(node)
			add_children(rule.notSet(), node)
		elif lexer_atom and rule.characterRange():
			print('characterRange', rule.characterRange())
		elif lexer_atom and rule.LEXER_CHAR_SET():
			print('charSet', str(rule.LEXER_CHAR_SET()), process_charset(str(rule.LEXER_CHAR_SET())))
		else:
			add_children(rule, parent)

	elif isinstance(rule, ANTLRv4Parser.SetElementContext):
		if rule.TOKEN_REF():
			node = TokenRefNode(str(rule.TOKEN_REF()))
			parent.add_child(node)
		elif rule.STRING_LITERAL():
			node = StringLiteralNode(str(rule.STRING_LITERAL()))
			parent.add_child(node)
		elif rule.characterRange():
			print('characterRange', rule.characterRange())
		elif rule.LEXER_CHAR_SET():
			print('charSet', str(rule.LEXER_CHAR_SET()), process_charset(str(rule.LEXER_CHAR_SET())))

	elif isinstance(rule, ParserRuleContext):
		add_children(rule, parent)

node = Node()
build_graph(current_root, node)
print(node.children[11].children)

# def build_expr(node):
# 	print(type(node))

# 	if isinstance(node, ANTLRv4Parser.ParserRuleSpecContext):
# 		print(str(node.RULE_REF()))

# 		if node.getChildCount():
# 			for child in node.children:
# 				build_expr(child)
# 	elif isinstance(node, ANTLRv4Parser.LabeledAltContext):
# 		if not node.identifier():
# 			build_expr(node.alternative())
# 			return

# 		print(str(node.identifier().TOKEN_REF() or node.identifier().RULE_REF()))
# 	elif isinstance(node, (ANTLRv4Parser.ElementContext, ANTLRv4Parser.LexerElementContext)):
# 		if node.actionBlock():
# 			print(''.join(str(child) for child in node.actionBlock().ACTION_CONTENT()))
# 			return

# 		suffix = None
# 		if node.ebnfSuffix():
# 			suffix = node.ebnfSuffix()
# 		elif hasattr(node, 'ebnf') and node.ebnf() and node.ebnf().blockSuffix():
# 			suffix = node.ebnf().blockSuffix().ebnfSuffix()

# 		if not suffix:
# 			build_expr(node.children[0])
# 			return

# 		print('QUANT', str(suffix.children[0]))
# 	elif isinstance(node, ANTLRv4Parser.RulerefContext):
# 		print('RULE_REF', str(node.RULE_REF()))
# 	elif isinstance(node, ANTLRv4Parser.TerminalContext):
# 		if node.TOKEN_REF():
# 			print('TOKEN_REF', node.TOKEN_REF())
# 		elif node.STRING_LITERAL():
# 			print('STRING_LITERAL', node.STRING_LITERAL())
# 	elif isinstance(node, ParserRuleContext):
# 		if node.getChildCount():
# 			for child in node.children:
# 				build_expr(child)

# build_expr(current_root)