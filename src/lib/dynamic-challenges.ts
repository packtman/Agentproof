/**
 * Dynamic Challenge Generator
 * Uses AI to generate unique code bugs on-the-fly
 * This makes challenges impossible to pre-memorize or farm
 */

// Bug templates with parameterizable elements
const BUG_TEMPLATES = [
  {
    type: "off-by-one",
    languages: ["python", "javascript", "typescript"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.arrayVar}):
    """${params.docstring}"""
    result = []
    for i in range(1, len(${params.arrayVar})):
        result.append(${params.arrayVar}[i] ${params.operation} ${params.operand})
    return result`,
      answer: {
        line: 4,
        issue: `Loop starts at index 1, skipping the first element of ${params.arrayVar}`,
        fix: `for i in range(len(${params.arrayVar})):`,
      },
    }),
    generateJavascript: (params: BugParams) => ({
      code: `function ${params.funcName}(${params.arrayVar}) {
    // ${params.docstring}
    const result = [];
    for (let i = 1; i < ${params.arrayVar}.length; i++) {
        result.push(${params.arrayVar}[i] ${params.operation} ${params.operand});
    }
    return result;
}`,
      answer: {
        line: 4,
        issue: `Loop starts at index 1, skipping the first element of ${params.arrayVar}`,
        fix: `for (let i = 0; i < ${params.arrayVar}.length; i++)`,
      },
    }),
  },
  {
    type: "wrong-comparison",
    languages: ["python", "javascript"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.valueVar}, ${params.thresholdVar}):
    """${params.docstring}"""
    if ${params.valueVar} > ${params.thresholdVar}:
        return "${params.successMsg}"
    elif ${params.valueVar} = ${params.thresholdVar}:
        return "${params.equalMsg}"
    else:
        return "${params.failMsg}"`,
      answer: {
        line: 5,
        issue: "Single equals sign is assignment, not comparison. Should use ==",
        fix: `elif ${params.valueVar} == ${params.thresholdVar}:`,
      },
    }),
    generateJavascript: (params: BugParams) => ({
      code: `function ${params.funcName}(${params.valueVar}, ${params.thresholdVar}) {
    // ${params.docstring}
    if (${params.valueVar} > ${params.thresholdVar}) {
        return "${params.successMsg}";
    } else if (${params.valueVar} = ${params.thresholdVar}) {
        return "${params.equalMsg}";
    } else {
        return "${params.failMsg}";
    }
}`,
      answer: {
        line: 5,
        issue: "Single equals sign is assignment, not comparison. Should use === or ==",
        fix: `} else if (${params.valueVar} === ${params.thresholdVar}) {`,
      },
    }),
  },
  {
    type: "null-check-missing",
    languages: ["python", "javascript", "typescript"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.objVar}):
    """${params.docstring}"""
    ${params.resultVar} = ${params.objVar}["${params.keyName}"]
    return ${params.resultVar}.${params.methodName}()`,
      answer: {
        line: 3,
        issue: `No null/None check before accessing "${params.keyName}" - will raise KeyError if key missing`,
        fix: `${params.resultVar} = ${params.objVar}.get("${params.keyName}")`,
      },
    }),
    generateJavascript: (params: BugParams) => ({
      code: `function ${params.funcName}(${params.objVar}) {
    // ${params.docstring}
    const ${params.resultVar} = ${params.objVar}.${params.keyName};
    return ${params.resultVar}.${params.methodName}();
}`,
      answer: {
        line: 3,
        issue: `No null check before accessing "${params.keyName}" - will throw TypeError if undefined`,
        fix: `const ${params.resultVar} = ${params.objVar}?.${params.keyName};`,
      },
    }),
  },
  {
    type: "infinite-recursion",
    languages: ["python", "javascript"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.numVar}):
    """${params.docstring}"""
    if ${params.numVar} == 0:
        return ${params.baseValue}
    return ${params.numVar} ${params.operation} ${params.funcName}(${params.numVar})`,
      answer: {
        line: 5,
        issue: `Infinite recursion - ${params.numVar} is never decremented in recursive call`,
        fix: `return ${params.numVar} ${params.operation} ${params.funcName}(${params.numVar} - 1)`,
      },
    }),
    generateJavascript: (params: BugParams) => ({
      code: `function ${params.funcName}(${params.numVar}) {
    // ${params.docstring}
    if (${params.numVar} === 0) {
        return ${params.baseValue};
    }
    return ${params.numVar} ${params.operation} ${params.funcName}(${params.numVar});
}`,
      answer: {
        line: 6,
        issue: `Infinite recursion - ${params.numVar} is never decremented in recursive call`,
        fix: `return ${params.numVar} ${params.operation} ${params.funcName}(${params.numVar} - 1);`,
      },
    }),
  },
  {
    type: "wrong-return-type",
    languages: ["python", "javascript"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.arrayVar}):
    """${params.docstring}"""
    if not ${params.arrayVar}:
        return 0
    ${params.resultVar} = 0
    for ${params.itemVar} in ${params.arrayVar}:
        ${params.resultVar} += ${params.itemVar}
    return "${params.resultVar}"`,
      answer: {
        line: 8,
        issue: `Returns string "${params.resultVar}" instead of the numeric variable ${params.resultVar}`,
        fix: `return ${params.resultVar}`,
      },
    }),
    generateJavascript: (params: BugParams) => ({
      code: `function ${params.funcName}(${params.arrayVar}) {
    // ${params.docstring}
    if (!${params.arrayVar} || ${params.arrayVar}.length === 0) {
        return 0;
    }
    let ${params.resultVar} = 0;
    for (const ${params.itemVar} of ${params.arrayVar}) {
        ${params.resultVar} += ${params.itemVar};
    }
    return "${params.resultVar}";
}`,
      answer: {
        line: 10,
        issue: `Returns string "${params.resultVar}" instead of the numeric variable ${params.resultVar}`,
        fix: `return ${params.resultVar};`,
      },
    }),
  },
  {
    type: "async-missing-await",
    languages: ["javascript", "typescript"],
    generateJavascript: (params: BugParams) => ({
      code: `async function ${params.funcName}(${params.idVar}) {
    // ${params.docstring}
    const ${params.resultVar} = ${params.asyncFuncName}(${params.idVar});
    if (!${params.resultVar}) {
        throw new Error("${params.errorMsg}");
    }
    return ${params.resultVar}.${params.propName};
}`,
      answer: {
        line: 3,
        issue: `Missing await - ${params.asyncFuncName} is async but result is a Promise, not the resolved value`,
        fix: `const ${params.resultVar} = await ${params.asyncFuncName}(${params.idVar});`,
      },
    }),
  },
  {
    type: "boundary-condition",
    languages: ["python", "javascript"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.arrayVar}, ${params.targetVar}):
    """${params.docstring}"""
    ${params.leftVar} = 0
    ${params.rightVar} = len(${params.arrayVar})
    while ${params.leftVar} < ${params.rightVar}:
        ${params.midVar} = (${params.leftVar} + ${params.rightVar}) // 2
        if ${params.arrayVar}[${params.midVar}] < ${params.targetVar}:
            ${params.leftVar} = ${params.midVar}
        else:
            ${params.rightVar} = ${params.midVar}
    return ${params.leftVar}`,
      answer: {
        line: 8,
        issue: `Setting ${params.leftVar} = ${params.midVar} can cause infinite loop when ${params.leftVar} + 1 == ${params.rightVar}`,
        fix: `${params.leftVar} = ${params.midVar} + 1`,
      },
    }),
    generateJavascript: (params: BugParams) => ({
      code: `function ${params.funcName}(${params.arrayVar}, ${params.targetVar}) {
    // ${params.docstring}
    let ${params.leftVar} = 0;
    let ${params.rightVar} = ${params.arrayVar}.length;
    while (${params.leftVar} < ${params.rightVar}) {
        const ${params.midVar} = Math.floor((${params.leftVar} + ${params.rightVar}) / 2);
        if (${params.arrayVar}[${params.midVar}] < ${params.targetVar}) {
            ${params.leftVar} = ${params.midVar};
        } else {
            ${params.rightVar} = ${params.midVar};
        }
    }
    return ${params.leftVar};
}`,
      answer: {
        line: 8,
        issue: `Setting ${params.leftVar} = ${params.midVar} can cause infinite loop when ${params.leftVar} + 1 == ${params.rightVar}`,
        fix: `${params.leftVar} = ${params.midVar} + 1;`,
      },
    }),
  },
  {
    type: "mutable-default-arg",
    languages: ["python"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.itemVar}, ${params.listVar}=[]):
    """${params.docstring}"""
    ${params.listVar}.append(${params.itemVar})
    return ${params.listVar}

# ${params.commentLine}`,
      answer: {
        line: 1,
        issue: "Mutable default argument - list persists between function calls",
        fix: `def ${params.funcName}(${params.itemVar}, ${params.listVar}=None):\n    ${params.listVar} = ${params.listVar} or []`,
      },
    }),
  },
  {
    type: "string-mutation",
    languages: ["python"],
    generatePython: (params: BugParams) => ({
      code: `def ${params.funcName}(${params.stringVar}):
    """${params.docstring}"""
    for i, ${params.charVar} in enumerate(${params.stringVar}):
        if ${params.charVar} == "${params.targetChar}":
            ${params.stringVar}[i] = "${params.replacementChar}"
    return ${params.stringVar}`,
      answer: {
        line: 4,
        issue: "Strings are immutable in Python - cannot assign to index",
        fix: `${params.stringVar} = ${params.stringVar}[:i] + "${params.replacementChar}" + ${params.stringVar}[i+1:]`,
      },
    }),
  },
  {
    type: "type-coercion",
    languages: ["javascript"],
    generateJavascript: (params: BugParams) => ({
      code: `function ${params.funcName}(${params.inputVar}) {
    // ${params.docstring}
    const ${params.resultVar} = ${params.inputVar} + ${params.operand};
    if (${params.resultVar} == "${params.expectedValue}") {
        return true;
    }
    return false;
}
// ${params.commentLine}`,
      answer: {
        line: 4,
        issue: `Using == instead of === allows type coercion - "${params.expectedValue}" comparison may behave unexpectedly`,
        fix: `if (${params.resultVar} === ${params.expectedValue}) {`,
      },
    }),
  },
];

interface BugParams {
  funcName: string;
  arrayVar: string;
  valueVar: string;
  thresholdVar: string;
  numVar: string;
  objVar: string;
  keyName: string;
  resultVar: string;
  methodName: string;
  itemVar: string;
  listVar: string;
  stringVar: string;
  charVar: string;
  targetChar: string;
  replacementChar: string;
  leftVar: string;
  rightVar: string;
  midVar: string;
  targetVar: string;
  idVar: string;
  asyncFuncName: string;
  propName: string;
  inputVar: string;
  operand: number;
  expectedValue: string;
  baseValue: number;
  operation: string;
  docstring: string;
  successMsg: string;
  equalMsg: string;
  failMsg: string;
  errorMsg: string;
  commentLine: string;
}

// Word pools for generating unique names
const FUNC_PREFIXES = ["calculate", "process", "validate", "transform", "compute", "analyze", "extract", "filter", "aggregate", "normalize"];
const FUNC_SUFFIXES = ["data", "values", "items", "records", "entries", "elements", "results", "metrics", "scores", "totals"];
const VAR_NAMES = {
  array: ["items", "values", "data", "records", "entries", "elements", "numbers", "scores", "inputs", "collection"],
  value: ["val", "num", "amount", "score", "count", "level", "rating", "price", "quantity", "total"],
  threshold: ["limit", "max", "min", "threshold", "boundary", "cap", "ceiling", "floor", "target", "cutoff"],
  obj: ["obj", "record", "item", "entry", "config", "settings", "options", "params", "payload", "response"],
  key: ["id", "name", "type", "status", "value", "code", "key", "label", "title", "category"],
  result: ["result", "output", "sum", "total", "answer", "value", "computed", "calculated", "processed", "final"],
  item: ["item", "elem", "val", "entry", "x", "n", "v", "curr", "current", "el"],
  char: ["char", "ch", "c", "letter", "symbol", "character"],
  left: ["left", "lo", "start", "begin", "low", "first", "i"],
  right: ["right", "hi", "end", "finish", "high", "last", "j"],
  mid: ["mid", "middle", "center", "pivot", "m"],
  id: ["id", "userId", "itemId", "recordId", "entityId", "key", "identifier"],
  async: ["fetchData", "loadRecord", "getUser", "retrieveItem", "queryDatabase", "fetchResource"],
  prop: ["data", "value", "result", "content", "payload", "body", "response", "output"],
  input: ["input", "value", "data", "num", "x", "arg", "param"],
};
const OPERATIONS = ["+", "*"];
const OPERANDS = [1, 2, 10, 100];
const CHARS = ["a", "e", "i", "o", "u", " ", "-", "_", "."];
const DOCSTRINGS = [
  "Process and return transformed values",
  "Calculate aggregated result from input",
  "Validate and return processed data",
  "Transform input according to rules",
  "Compute the final result value",
  "Analyze and return findings",
  "Extract relevant information from input",
  "Filter and return matching items",
];

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateUniqueParams(): BugParams {
  return {
    funcName: `${randomChoice(FUNC_PREFIXES)}_${randomChoice(FUNC_SUFFIXES)}`,
    arrayVar: randomChoice(VAR_NAMES.array),
    valueVar: randomChoice(VAR_NAMES.value),
    thresholdVar: randomChoice(VAR_NAMES.threshold),
    numVar: randomChoice(VAR_NAMES.value),
    objVar: randomChoice(VAR_NAMES.obj),
    keyName: randomChoice(VAR_NAMES.key),
    resultVar: randomChoice(VAR_NAMES.result),
    methodName: randomChoice(["toString", "toLowerCase", "toUpperCase", "trim", "strip"]),
    itemVar: randomChoice(VAR_NAMES.item),
    listVar: randomChoice(VAR_NAMES.array),
    stringVar: "text",
    charVar: randomChoice(VAR_NAMES.char),
    targetChar: randomChoice(CHARS),
    replacementChar: randomChoice(CHARS),
    leftVar: randomChoice(VAR_NAMES.left),
    rightVar: randomChoice(VAR_NAMES.right),
    midVar: randomChoice(VAR_NAMES.mid),
    targetVar: "target",
    idVar: randomChoice(VAR_NAMES.id),
    asyncFuncName: randomChoice(VAR_NAMES.async),
    propName: randomChoice(VAR_NAMES.prop),
    inputVar: randomChoice(VAR_NAMES.input),
    operand: randomChoice(OPERANDS),
    expectedValue: String(randomChoice([10, 100, 1000, "valid", "ok"])),
    baseValue: randomChoice([0, 1]),
    operation: randomChoice(OPERATIONS),
    docstring: randomChoice(DOCSTRINGS),
    successMsg: randomChoice(["valid", "success", "passed", "ok", "approved"]),
    equalMsg: randomChoice(["equal", "match", "same", "exact", "tie"]),
    failMsg: randomChoice(["invalid", "failed", "rejected", "error", "denied"]),
    errorMsg: randomChoice(["Not found", "Invalid data", "Missing required field", "Operation failed"]),
    commentLine: randomChoice([
      "Called multiple times in a loop",
      "Used for batch processing",
      "Part of the validation pipeline",
      "Returns processed result",
    ]),
  };
}

export interface DynamicChallenge {
  id: string;
  language: string;
  code: string;
  answer: {
    line: number;
    issue: string;
    fix: string;
  };
  difficulty: "easy" | "standard" | "hard";
  bugType: string;
  generatedAt: string;
}

/**
 * Generate a unique code bug challenge
 * Each challenge has randomized:
 * - Function/variable names
 * - Bug type
 * - Language
 * - Context/docstrings
 */
export function generateDynamicChallenge(
  difficulty: "easy" | "standard" | "hard" = "standard"
): DynamicChallenge {
  const params = generateUniqueParams();
  
  // Select bug types based on difficulty
  const easyTypes = ["off-by-one", "wrong-return-type", "null-check-missing"];
  const standardTypes = ["wrong-comparison", "infinite-recursion", "async-missing-await", "mutable-default-arg"];
  const hardTypes = ["boundary-condition", "type-coercion", "string-mutation"];
  
  let eligibleTypes: string[];
  switch (difficulty) {
    case "easy":
      eligibleTypes = easyTypes;
      break;
    case "standard":
      eligibleTypes = [...easyTypes, ...standardTypes];
      break;
    case "hard":
      eligibleTypes = [...standardTypes, ...hardTypes];
      break;
  }
  
  const bugType = randomChoice(eligibleTypes);
  const template = BUG_TEMPLATES.find(t => t.type === bugType);
  
  if (!template) {
    throw new Error(`Unknown bug type: ${bugType}`);
  }
  
  // Select language
  const language = randomChoice(template.languages);
  
  // Generate the code and answer
  const generator = language === "python" 
    ? (template as any).generatePython 
    : (template as any).generateJavascript;
    
  if (!generator) {
    // Fallback to another template if generator doesn't exist for this language
    return generateDynamicChallenge(difficulty);
  }
  
  const { code, answer } = generator(params);
  
  return {
    id: `dyn_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    language,
    code,
    answer,
    difficulty,
    bugType,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Validate answer against a dynamic challenge
 * More flexible than static validation since names vary
 */
export function validateDynamicAnswer(
  challenge: DynamicChallenge,
  answer: { line: number; issue: string; fix?: string }
): { passed: boolean; error?: string; confidence: number } {
  // Check line number (allow +/- 1 tolerance)
  if (Math.abs(answer.line - challenge.answer.line) > 1) {
    return {
      passed: false,
      error: `Incorrect line number. Expected around line ${challenge.answer.line}`,
      confidence: 0,
    };
  }
  
  // Extract key concepts from the expected issue description
  const issueLC = challenge.answer.issue.toLowerCase();
  const answerIssueLC = answer.issue.toLowerCase();
  
  // Bug-type specific keyword matching
  const bugKeywords: Record<string, string[]> = {
    "off-by-one": ["index", "skip", "first", "start", "1", "begin", "missing"],
    "wrong-comparison": ["assignment", "==", "equals", "comparison", "single", "="],
    "null-check-missing": ["null", "undefined", "check", "missing", "keyerror", "typeerror"],
    "infinite-recursion": ["infinite", "recursion", "decrement", "never", "loop", "stack"],
    "wrong-return-type": ["string", "return", "variable", "type", "quotes"],
    "async-missing-await": ["await", "async", "promise", "missing"],
    "boundary-condition": ["infinite", "loop", "boundary", "+1", "plus one", "mid"],
    "mutable-default-arg": ["mutable", "default", "argument", "persist", "list", "shared"],
    "string-mutation": ["immutable", "string", "assign", "index", "cannot"],
    "type-coercion": ["coercion", "===", "==", "type", "strict"],
  };
  
  const keywords = bugKeywords[challenge.bugType] || [];
  const matchedKeywords = keywords.filter(kw => answerIssueLC.includes(kw));
  
  // Need at least 2 matching keywords or 40% of keywords
  const minMatches = Math.max(2, Math.floor(keywords.length * 0.4));
  const confidence = matchedKeywords.length / keywords.length;
  
  if (matchedKeywords.length < minMatches) {
    return {
      passed: false,
      error: "Issue description does not correctly identify the bug",
      confidence,
    };
  }
  
  return { passed: true, confidence };
}

/**
 * LLM-powered challenge generation (optional, for even more variety)
 * Requires OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable
 */
export async function generateLLMChallenge(
  difficulty: "easy" | "standard" | "hard" = "standard"
): Promise<DynamicChallenge | null> {
  const apiKey = process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY;
  
  if (!apiKey) {
    // Fall back to template-based generation
    return generateDynamicChallenge(difficulty);
  }
  
  // TODO: Implement LLM-based generation
  // This would call OpenAI/Anthropic to generate truly unique bugs
  // For now, use template-based generation
  return generateDynamicChallenge(difficulty);
}
