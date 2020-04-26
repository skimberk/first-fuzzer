import re
from enum import Enum, auto
from collections import namedtuple

from antlr4 import CommonTokenStream, FileStream, ParserRuleContext

from antlr_stuff.compiled.ANTLRv4Parser import ANTLRv4Parser
from antlr_stuff.compiled.ANTLRv4Lexer import ANTLRv4Lexer

from charset_parser import lexer_charset_interval

class NodeType(Enum):
	ROOT = auto()
	PARSER_RULE = auto()
	LEXER_RULE = auto()
	RULE_REF = auto()
	TOKEN_REF = auto()
	QUANTIFIER = auto()
	ALTERNATIVE = auto()
	STRING_LITERAL = auto()
	CHAR_SET = auto()
	NOT = auto()
	DOT = auto()

LEAF_TYPES = [
	NodeType.RULE_REF,
	NodeType.TOKEN_REF,
	NodeType.STRING_LITERAL,
	NodeType.CHAR_SET,
	NodeType.DOT
]

Node = namedtuple('Node', ['type', 'value'])
Graph = namedtuple('Graph', ['nodes', 'edges'])

def build_graph(rule):
	nodes = []
	edges = []

	def add_node(node):
		nodes.append(node)
		edges.append([])
		return len(nodes) - 1

	def add_edge(parent, child):
		edges[parent].append(child)

	def add_child(parent_id, child):
		child_id = add_node(child)
		add_edge(parent_id, child_id)
		return child_id

	def add_children(rule, node):
		if rule.getChildCount():
			for child in rule.children:
				_build_graph(child, node)

	def _build_graph(rule, parent):
		if isinstance(rule, ANTLRv4Parser.ParserRuleSpecContext):
			node = Node(NodeType.PARSER_RULE, str(rule.RULE_REF()))
			node_id = add_child(parent, node)
			add_children(rule, node_id)

		elif isinstance(rule, ANTLRv4Parser.LexerRuleSpecContext):
			node = Node(NodeType.LEXER_RULE, str(rule.TOKEN_REF()))
			node_id = add_child(parent, node)
			add_children(rule, node_id)

		elif isinstance(rule, (ANTLRv4Parser.ElementContext, ANTLRv4Parser.LexerElementContext)):
			suffix = None
			if rule.ebnfSuffix():
				suffix = rule.ebnfSuffix()
			elif hasattr(rule, 'ebnf') and rule.ebnf() and rule.ebnf().blockSuffix():
				suffix = rule.ebnf().blockSuffix().ebnfSuffix()

			if suffix:
				node = Node(NodeType.QUANTIFIER, str(suffix.children[0]))
				node_id = add_child(parent, node)
				add_children(rule, node_id)
			else:
				_build_graph(rule.children[0], parent)

		elif isinstance(rule, ANTLRv4Parser.RulerefContext):
			node = Node(NodeType.RULE_REF, str(rule.RULE_REF()))
			add_child(parent, node)

		elif isinstance(rule, ANTLRv4Parser.TerminalContext):
			if rule.TOKEN_REF():
				node = Node(NodeType.TOKEN_REF, str(rule.TOKEN_REF()))
				add_child(parent, node)
			elif rule.STRING_LITERAL():
				node = Node(NodeType.STRING_LITERAL, str(rule.STRING_LITERAL()))
				add_child(parent, node)

		elif isinstance(rule, ANTLRv4Parser.LabeledAltContext):
			label = None
			if rule.identifier() and (rule.identifier().TOKEN_REF() or rule.identifier().RULE_REF()):
				label = str(rule.identifier().TOKEN_REF() or rule.identifier().RULE_REF())

			node = Node(NodeType.ALTERNATIVE, label)
			node_id = add_child(parent, node)
			add_children(rule.alternative(), node_id)

		elif isinstance(rule, (ANTLRv4Parser.AtomContext, ANTLRv4Parser.LexerAtomContext)):
			lexer_atom = isinstance(rule, ANTLRv4Parser.LexerAtomContext)

			if rule.DOT():
				node = Node(NodeType.DOT, None)
				add_child(parent, node)
			elif rule.notSet():
				node = Node(NodeType.NOT, None)
				node_id = add_child(parent, node)
				add_children(rule.notSet(), node_id)
			elif lexer_atom and rule.characterRange():
				print('TODO: characterRange', rule.characterRange())
			elif lexer_atom and rule.LEXER_CHAR_SET():
				char_set = lexer_charset_interval(str(rule.LEXER_CHAR_SET())[1:-1])
				node = Node(NodeType.CHAR_SET, char_set)
				add_child(parent, node)
			else:
				add_children(rule, parent)

		elif isinstance(rule, ANTLRv4Parser.SetElementContext):
			if rule.TOKEN_REF():
				node = Node(NodeType.TOKEN_REF, str(rule.TOKEN_REF()))
				add_child(parent, node)
			elif rule.STRING_LITERAL():
				node = Node(NodeType.STRING_LITERAL, str(rule.STRING_LITERAL()))
				add_child(parent, node)
			elif rule.characterRange():
				print('TODO: characterRange', rule.characterRange())
			elif rule.LEXER_CHAR_SET():
				char_set = lexer_charset_interval(str(rule.LEXER_CHAR_SET())[1:-1])
				node = Node(NodeType.CHAR_SET, char_set)
				add_child(parent, node)

		elif isinstance(rule, ParserRuleContext):
			add_children(rule, parent)

	root_id = add_node(Node(NodeType.ROOT, None))
	_build_graph(rule, root_id)

	return Graph(nodes, edges)

antlr_parser = ANTLRv4Parser(CommonTokenStream(ANTLRv4Lexer(FileStream('JSON.g4', encoding='utf-8'))))
current_root = antlr_parser.grammarSpec()
graph = build_graph(current_root)

print(graph)
