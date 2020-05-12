from enum import Enum
from random import randrange

class E(Enum):
	JSON = 1
	OBJ = 2
	OBJ_MORE = 3
	ARR = 4
	ARR_MORE = 5
	BOOL = 6
	STR = 7
	STR_MORE = 8
	NUM = 9

json_grammar = {
	E.JSON: [[E.OBJ], [E.ARR], [E.BOOL], [E.STR]], # TODO: Add E.NUM
	E.OBJ: [['{}'], ['{', E.STR, ': ', E.JSON, E.OBJ_MORE, '}']],
	E.OBJ_MORE: [[''], [', ', E.STR, ': ', E.JSON, E.OBJ_MORE]],
	E.ARR: [['[]'], ['[', E.JSON, E.ARR_MORE, ']']],
	E.ARR_MORE: [[''], [', ', E.JSON, E.ARR_MORE]],
	E.BOOL: [['true'], ['false']],
	E.STR: [['"', E.STR_MORE, '"']],
	E.STR_MORE: [[''], ['a', E.STR_MORE], ['b', E.STR_MORE], ['c', E.STR_MORE]]
}

def random_string(grammar, start):
	index = randrange(len(grammar[start]))
	part = grammar[start][index]

	output = ''
	for x in part:
		if isinstance(x, E):
			output += random_string(grammar, x)
		else:
			output += x

	return output

print(random_string(json_grammar, E.JSON))