import sys
import random

for line in sys.stdin:
	print(line)

if random.randrange(10) == 0:
	raise Exception('Failure!!!')
