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
			print('charSet', rule.LEXER_CHAR_SET())
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
			print('charSet', rule.LEXER_CHAR_SET())

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