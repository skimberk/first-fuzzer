import re
from enum import Enum, auto

from antlr4 import CommonTokenStream, FileStream, ParserRuleContext

from antlr_stuff.compiled.ANTLRv4Parser import ANTLRv4Parser
from antlr_stuff.compiled.ANTLRv4Lexer import ANTLRv4Lexer

from charset_parser import lexer_charset_interval

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

antlr_parser = ANTLRv4Parser(CommonTokenStream(ANTLRv4Lexer(FileStream('JSON.g4', encoding='utf-8'))))
current_root = antlr_parser.grammarSpec()

node = Node()
build_graph(current_root, node)
print(node.children[11].children)
