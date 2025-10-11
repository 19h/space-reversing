const fs = require('fs');

// Define primitive types to ignore (expand as needed based on common C++ types in the header)
const primitives = new Set([
  'bool', 'char', 'short', 'int', 'long', 'float', 'double',
  'unsigned', 'signed', // Modifiers, but often combined
  'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
  'int8_t', 'int16_t', 'int32_t', 'int64_t',
  'size_t', 'uintptr_t', 'ptrdiff_t', 'void'
]);

// Function to parse the header file and extract structs and their dependencies
function parseStructs(fileContent) {
  const lines = fileContent.split('\n');
  const structs = {}; // name => full definition text
  const calleesMap = {}; // name => Set of referenced struct names (callees)
  let currentStruct = null;
  let currentLines = [];
  let inStructBlock = false;

  lines.forEach((line) => {
    if (line.trim().startsWith('// Original name:')) {
      // Start of a new struct block
      if (currentStruct && currentLines.length > 0) {
        structs[currentStruct] = currentLines.join('\n');
      }
      currentLines = [line];
      currentStruct = null;
      inStructBlock = false;
    } else if (line.match(/struct\s+(\w+)\s*\{/)) {
      currentStruct = RegExp.$1;
      currentLines.push(line);
      inStructBlock = true;
    } else if (inStructBlock && line.trim() === '};') {
      currentLines.push(line);
      inStructBlock = false;
      // Save the struct now if complete
      if (currentStruct && currentLines.length > 0) {
        structs[currentStruct] = currentLines.join('\n');
      }
    } else if (currentLines.length > 0) {
      currentLines.push(line);
    }
  });

  // Save the last struct if any
  if (currentStruct && currentLines.length > 0) {
    structs[currentStruct] = currentLines.join('\n');
  }

  // Now parse callees for each struct
  Object.keys(structs).forEach((name) => {
    calleesMap[name] = new Set();
    const def = structs[name];
    const structLines = def.split('\n');
    let inBody = false;
    structLines.forEach((line) => {
      if (line.includes('{')) {
        inBody = true;
        return;
      }
      if (line.trim() === '};') {
        inBody = false;
        return;
      }
      if (inBody && line.trim() && !line.trim().startsWith('//')) {
        // Parse field: e.g., "Vec3 size; // Offset: 0x38"
        const fieldDecl = line.split(';')[0].trim();
        if (!fieldDecl) return;
        const parts = fieldDecl.split(/\s+/);
        if (parts.length < 2) return;
        const declarator = parts.pop();
        let typeStr = parts.join(' ');
        // Remove trailing * if present (pointer)
        let baseType = typeStr.replace(/\*$/, '').trim();
        let refType;
        if (baseType.startsWith('DynArray_')) {
          // Handle templated like DynArray_VisorLens_Widget
          refType = baseType.substring('DynArray_'.length);
        } else {
          refType = baseType;
        }
        // Split combined types if needed (e.g., 'unsigned int' but in example single words)
        const potentialRefs = refType.split(/\s+/).filter(t => t);
        potentialRefs.forEach((t) => {
          if (!primitives.has(t) && structs[t]) {
            calleesMap[name].add(t);
          }
        });
      }
    });
  });

  return { structs, calleesMap };
}

// Function to build callers map (reverse of callees)
function buildCallersMap(calleesMap) {
  const callersMap = {};
  Object.keys(calleesMap).forEach((name) => {
    if (!callersMap[name]) callersMap[name] = new Set();
    calleesMap[name].forEach((callee) => {
      if (!callersMap[callee]) callersMap[callee] = new Set();
      callersMap[callee].add(name);
    });
  });
  return callersMap;
}

// Function to get all transitive dependencies (BFS)
function getTransitive(start, graph, includeSelf = false) {
  const visited = new Set();
  const queue = [start];
  while (queue.length > 0) {
    const curr = queue.shift();
    if (visited.has(curr)) continue;
    visited.add(curr);
    if (graph[curr]) {
      graph[curr].forEach((next) => queue.push(next));
    }
  }
  if (!includeSelf) visited.delete(start);
  return visited;
}

// Main execution
function main() {
  if (process.argv.length !== 4) {
    console.error('Usage: node script.js <struct_name> <output_file>');
    process.exit(1);
  }

  const startStruct = process.argv[2];
  const outputFile = process.argv[3];

  let fileContent;
  try {
    fileContent = fs.readFileSync('datacore-structs.h', 'utf8');
  } catch (err) {
    console.error('Error reading datacore-structs.h:', err.message);
    process.exit(1);
  }

  const { structs, calleesMap } = parseStructs(fileContent);
  const callersMap = buildCallersMap(calleesMap);

  if (!structs[startStruct]) {
    console.error(`Struct ${startStruct} not found in datacore-structs.h`);
    process.exit(1);
  }

  // Get all transitive callees (referenced structs and their refs)
  const allCallees = getTransitive(startStruct, calleesMap);

  // Get all transitive callers (structs referencing this and their refs)
  const allCallers = getTransitive(startStruct, callersMap);

  // Combine: start + callees + callers
  const allRelated = new Set([startStruct, ...allCallees, ...allCallers]);

  // Collect definitions, sort by name for consistent order
  const outputDefs = Array.from(allRelated)
    .sort()
    .map((name) => structs[name])
    .join('\n\n');

  try {
    fs.writeFileSync(outputFile, outputDefs, 'utf8');
    console.log(`Output written to ${outputFile}`);
  } catch (err) {
    console.error('Error writing output file:', err.message);
    process.exit(1);
  }
}

main();
