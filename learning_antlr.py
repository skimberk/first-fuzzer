from antlr4 import CommonTokenStream, FileStream, ParserRuleContext

from antlr_stuff.compiled.ANTLRv4Parser import ANTLRv4Parser
from antlr_stuff.compiled.ANTLRv4Lexer import ANTLRv4Lexer

antlr_parser = ANTLRv4Parser(CommonTokenStream(ANTLRv4Lexer(FileStream('JSON.g4', encoding='utf-8'))))
current_root = antlr_parser.grammarSpec()
print(current_root)
print(current_root.rules().ruleSpec())

node = current_root

for rule in node.rules().ruleSpec():
	print(type(rule).__name__)
	if rule.parserRuleSpec():
		rule_spec = rule.parserRuleSpec()
		print('parser', rule, str(rule_spec.RULE_REF()))
	elif rule.lexerRuleSpec():
		rule_spec = rule.lexerRuleSpec()
		print('lexer', rule, str(rule_spec.TOKEN_REF()))
	else:
		print('GAAAH')

def build_expr(node):
	print(type(node))

	if isinstance(node, ANTLRv4Parser.LabeledAltContext):
		if not node.identifier():
			build_expr(node.alternative())
			return

		print(str(node.identifier().TOKEN_REF() or node.identifier().RULE_REF()))
	elif isinstance(node, (ANTLRv4Parser.ElementContext, ANTLRv4Parser.LexerElementContext)):
		if node.actionBlock():
			print(''.join(str(child) for child in node.actionBlock().ACTION_CONTENT()))
			return

		suffix = None
		if node.ebnfSuffix():
			suffix = node.ebnfSuffix()
		elif hasattr(node, 'ebnf') and node.ebnf() and node.ebnf().blockSuffix():
			suffix = node.ebnf().blockSuffix().ebnfSuffix()

		if not suffix:
			build_expr(node.children[0])
			return

		print('QUANT', str(suffix.children[0]))
	elif isinstance(node, ANTLRv4Parser.RulerefContext):
		print('RULE_REF', str(node.RULE_REF()))
	elif isinstance(node, ANTLRv4Parser.TerminalContext):
		if node.TOKEN_REF():
			print('TOKEN_REF', node.TOKEN_REF())
		elif node.STRING_LITERAL():
			print('STRING_LITERAL', node.STRING_LITERAL())
	elif isinstance(node, ParserRuleContext):
		if node.getChildCount():
			for child in node.children:
				build_expr(child)

build_expr(node)