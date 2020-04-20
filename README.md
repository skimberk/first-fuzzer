## Python environment

First, create virtual environment for installing dependencies:

```
python3 -m venv env
```

Then, activate the virtual environment. You will do this whenever you start working on the project:

```
source env/bin/activate
```

To install dependencies:

```
python3 -m pip install -r requirements.txt
```


To leave the virtual environment:

```
deactivate
```

## Setting up ANTLR

Copied `ANTLRv4LexerPythonTarget.g4`, `ANTLRv4Parser.g4`, `LexBasic.g4`, and `LexerAdaptor.py` from the `antlr/grammars-v4` repo (located here: https://github.com/antlr/grammars-v4/tree/master/antlr/antlr4).

Renamed `ANTLRv4LexerPythonTarget.g4` to `ANTLRv4Lexer.g4` and also replaced occurences of former name with latter inside the file:

```
mv ANTLRv4LexerPythonTarget.g4 ANTLRv4Lexer.g4 && perl -pi -e s,ANTLRv4LexerPythonTarget,ANTLRv4Lexer,g ANTLRv4Lexer.g4
```

Downloaded ANTLR using:

```
curl -O https://www.antlr.org/download/antlr-4.8-complete.jar
```

Ran using:

```
java -jar antlr-4.8-complete.jar ...
```

So, for the ANTLRv4 grammar:

```
java -jar antlr-4.8-complete.jar -Dlanguage=Python3 ANTLRv4Lexer.g4 ANTLRv4Parser.g4 LexBasic.g4 -o compiled && cp LexerAdaptor.py compiled/LexerAdaptor.py
```

## Useful work

Generating code from ANTLR v4 grammars:
https://github.com/renatahodovan/grammarinator
(and the accompanying paper, "Grammarinator: A Grammar-Based Open Source Fuzzer", although it doesn't provide much insight)

Generate code and mutate test cases (precedes grammarinator):
"Fuzzing with Code Fragments" resulting in LangFuzz, however not open source.
https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final73.pdf

Generating code from grammars very quickly:
"Building Fast Fuzzers" resulting in F1 fuzzer, however not very useful. Not many options, unclear whether being fast is useful for us.
https://arxiv.org/pdf/1911.07707.pdf