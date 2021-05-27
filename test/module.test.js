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

test('normal behaviour', () => {
    console.time("analysis");
    let fbasAnalyzer = new FbasAnalyzer();
    let analysis = fbasAnalyzer.analyze(nodes, ['GCGB2S2KGYARPVIA37HYZXVRM2YZUEXA6S33ZU5BUDC6THSB62LZSTYH', 'GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK', 'GABMKJM6I25XI4K7U6XWMULOUQIQ27BCTMLS6BYYSOWKTBUXVRJSXHYQ'], organizations);
    //sdf org faulty
    expect(analysis.cache_hit).toBeFalsy();
    expect(analysis.top_tier.length).toEqual(23);
    expect(analysis.top_tier.includes('GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK')).toBeTruthy();
    expect(analysis.org_top_tier.length).toEqual(7);
    expect(analysis.has_symmetric_top_tier).toEqual(true);

    expect(analysis.minimal_blocking_sets.length).toEqual(1890);
    //smallest set size
    expect(Math.min.apply(Math, analysis.minimal_blocking_sets.map(mbs => mbs.length))).toEqual(6);
    //smallest set size is first
    expect(analysis.minimal_blocking_sets[0].length).toEqual(6);
    expect(Math.min.apply(Math, analysis.minimal_splitting_sets.map(mbs => mbs.length))).toEqual(3);
    //smallest set size is first
    expect(analysis.minimal_splitting_sets[0].length).toEqual(3);
    expect(analysis.org_minimal_blocking_sets[0].length).toEqual(3);
    expect(analysis.country_minimal_blocking_sets[0].length).toEqual(1);
    expect(analysis.isp_minimal_blocking_sets[0].length).toEqual(1);
    expect(analysis.org_minimal_blocking_sets.length).toEqual(35);

    expect(analysis.minimal_blocking_sets_faulty_nodes_filtered.length).toEqual(240);
    expect(analysis.minimal_blocking_sets_faulty_nodes_filtered[0].length).toEqual(4);

    expect(analysis.org_minimal_blocking_sets_faulty_nodes_filtered.length).toEqual(15);
    expect(analysis.org_minimal_blocking_sets_faulty_nodes_filtered[0].length).toEqual(2);
    expect(analysis.isp_minimal_blocking_sets_faulty_nodes_filtered[0].length).toEqual(1);
    expect(analysis.country_minimal_blocking_sets_faulty_nodes_filtered[0].length).toEqual(1);

    expect(analysis.org_minimal_splitting_sets[0].length).toEqual(3);
    expect(analysis.org_minimal_splitting_sets.length).toEqual(35);

    expect(analysis.country_minimal_splitting_sets[0].length).toEqual(1);
    expect(analysis.country_minimal_splitting_sets.length).toEqual(4);

    expect(analysis.isp_minimal_splitting_sets[0].length).toEqual(1);
    expect(analysis.isp_minimal_splitting_sets.length).toEqual(4);

    expect(analysis.has_quorum_intersection).toBeTruthy();
    analysis = fbasAnalyzer.analyze(nodes, ['GA35T3723UP2XJLC2H7MNL6VMKZZIFL2VW7XHMFFJKKIA2FJCYTLKFBW',
        'GA5STBMV6QDXFDGD62MEHLLHZTPDI77U3PFOD2SELU5RJDHQWBR5NNK7',
        'GAAV2GCVFLNN522ORUYFV33E76VPC22E72S75AQ6MBR5V45Z5DWVPWEU'], organizations);

    analysis = fbasAnalyzer.analyze(nodes, ['GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK'], organizations);
    expect(analysis.cache_hit).toBeTruthy();
    console.timeEnd("analysis");
})