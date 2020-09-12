const {FbasAnalyzer} = require('..');
const fs = require('fs');

let nodes;
let nodesOlder;
let organizations;

beforeEach(async () => {
    nodes = (await fs.promises.readFile('./seed/nodes.json')).toString();
    nodesOlder = (await fs.promises.readFile('./seed/nodes-older.json')).toString();
    organizations = (await fs.promises.readFile('./seed/organizations.json')).toString();
})

function filterValidator(publicKey, quorumSet){
    let index = quorumSet.validators.indexOf(publicKey);
    if (index > -1) {
        quorumSet.validators.splice(index, 1);
    }

    quorumSet.innerQuorumSets.forEach(quorumSet => filterValidator(publicKey, quorumSet));
}

test('quorum intersection when nodes are inactive', () => {
    let fbasAnalyzer = new FbasAnalyzer();
    let analysis = fbasAnalyzer.analyze(nodesOlder, [], organizations);
    let blockingSet = analysis.minimal_blocking_sets[0];

    analysis = fbasAnalyzer.analyze(nodesOlder, blockingSet, organizations);
    let quorumIntersectionWithEvilNodes = analysis.has_quorum_intersection;
    let quorumIntersectionWithoutEvilNodes = analysis.has_quorum_intersection_faulty_nodes_filtered;
    expect(analysis.minimal_blocking_sets_faulty_nodes_filtered[0]).toHaveLength(0);
    expect(quorumIntersectionWithEvilNodes).toBeTruthy();
    //if blocking set is regarded as evil:
    expect(quorumIntersectionWithoutEvilNodes).toBeTruthy();

    //let the blocking set fail, remove the nodes from the quorumsets.
    let nodesObjects = JSON.parse(nodesOlder);
    blockingSet.forEach(blockingNode => {
        nodesObjects.forEach(node =>
            filterValidator(blockingNode, node.quorumSet)
        );
    });

    analysis = fbasAnalyzer.analyze(JSON.stringify(nodesObjects), [], organizations);
    expect(analysis.minimal_blocking_sets_faulty_nodes_filtered).toHaveLength(0);
    expect(analysis.has_quorum_intersection).toEqual(false); //!!!this is different then regarding the blocking set as evil.

});

test('normal behaviour', () => {
    console.time("analysis");
    let fbasAnalyzer = new FbasAnalyzer();
    let analysis = fbasAnalyzer.analyze(nodes, ['GCGB2S2KGYARPVIA37HYZXVRM2YZUEXA6S33ZU5BUDC6THSB62LZSTYH', 'GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK', 'GABMKJM6I25XI4K7U6XWMULOUQIQ27BCTMLS6BYYSOWKTBUXVRJSXHYQ'], organizations);
    //sdf org faulty
    expect(analysis.cache_hit).toBeFalsy();
    expect(analysis.top_tier.length).toEqual(23);
    expect(analysis.top_tier_faulty_nodes_filtered.length).toEqual(20);
    expect(analysis.top_tier.includes('GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK')).toBeTruthy();
    expect(analysis.org_top_tier.length).toEqual(7);
    expect(analysis.org_top_tier_faulty_nodes_filtered.length).toEqual(6);

    expect(analysis.minimal_blocking_sets.length).toEqual(1890);
    //smallest set size
    expect(Math.min.apply(Math, analysis.minimal_blocking_sets.map(mbs => mbs.length))).toEqual(6);
    //smallest set size is first
    expect(analysis.minimal_blocking_sets[0].length).toEqual(6);
    expect(Math.min.apply(Math, analysis.minimal_splitting_sets.map(mbs => mbs.length))).toEqual(3);
    //smallest set size is first
    expect(analysis.minimal_splitting_sets[0].length).toEqual(3);
    expect(analysis.org_minimal_blocking_sets[0].length).toEqual(3);
    expect(analysis.org_minimal_blocking_sets.length).toEqual(35);

    expect(analysis.minimal_blocking_sets_faulty_nodes_filtered.length).toEqual(240);
    expect(analysis.minimal_blocking_sets_faulty_nodes_filtered[0].length).toEqual(4);

    expect(analysis.org_minimal_blocking_sets_faulty_nodes_filtered.length).toEqual(15);
    expect(analysis.org_minimal_blocking_sets_faulty_nodes_filtered[0].length).toEqual(2);

    expect(analysis.minimal_splitting_sets_faulty_nodes_filtered.length).toEqual(165);
    expect(analysis.minimal_splitting_sets_faulty_nodes_filtered[0].length).toEqual(2);

    expect(analysis.org_minimal_splitting_sets[0].length).toEqual(3);
    expect(analysis.org_minimal_splitting_sets.length).toEqual(35);

    expect(analysis.org_minimal_splitting_sets_faulty_nodes_filtered[0].length).toEqual(2);
    expect(analysis.org_minimal_splitting_sets_faulty_nodes_filtered.length).toEqual(15);

    expect(analysis.has_quorum_intersection).toBeTruthy();
    expect(analysis.has_quorum_intersection_faulty_nodes_filtered).toBeTruthy();
    analysis = fbasAnalyzer.analyze(nodes, ['GA35T3723UP2XJLC2H7MNL6VMKZZIFL2VW7XHMFFJKKIA2FJCYTLKFBW',
        'GA5STBMV6QDXFDGD62MEHLLHZTPDI77U3PFOD2SELU5RJDHQWBR5NNK7',
        'GAAV2GCVFLNN522ORUYFV33E76VPC22E72S75AQ6MBR5V45Z5DWVPWEU'], organizations);
    expect(analysis.has_quorum_intersection_faulty_nodes_filtered).toBeFalsy();

    analysis = fbasAnalyzer.analyze(nodes, ['GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK'], organizations);
    expect(analysis.cache_hit).toBeTruthy();
    console.timeEnd("analysis");
})