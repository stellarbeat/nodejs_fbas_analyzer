//const jestGlobals = require("@jest/globals");

const fbasAnalyzer = require('..');
const fs = require('fs');

let nodes;

beforeEach(async () => {
    nodes = (await fs.promises.readFile('./seed/nodes.json')).toString();
})

test('module', () => {
    console.time("analysis");
    console.log(nodes);
    console.log(fbasAnalyzer.analyze(nodes));
    console.timeEnd("analysis");
})