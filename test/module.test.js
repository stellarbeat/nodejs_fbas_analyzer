const {FbasAnalyzer} = require('..');
const fs = require('fs');

let nodes;

beforeEach(async () => {
    nodes = (await fs.promises.readFile('./seed/nodes.json')).toString();
})

test('module', () => {
    console.time("analysis");
    let fbasAnalyzer = new FbasAnalyzer();
    let analysis = fbasAnalyzer.analyze(nodes);
    expect(analysis.cache_hit).toBeFalsy();
    expect(analysis.top_tier.length).toEqual(23);
    expect(analysis.top_tier.includes('GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK')).toBeTruthy();
    expect(analysis.minimal_blocking_sets.length).toEqual(1890);
    //smallest set size
    expect(Math.min.apply(Math, analysis.minimal_blocking_sets.map(mbs => mbs.length))).toEqual(6);
    //smallest set size is first
    expect(analysis.minimal_blocking_sets[0].length).toEqual(6);
    expect(Math.min.apply(Math, analysis.minimal_splitting_sets.map(mbs => mbs.length))).toEqual(3);
    //smallest set size is first
    expect(analysis.minimal_splitting_sets[0].length).toEqual(3);

    //todo faulty nodes

    //todo organizations

    analysis = fbasAnalyzer.analyze(nodes);
    expect(analysis.cache_hit).toBeTruthy();
    console.timeEnd("analysis");
})