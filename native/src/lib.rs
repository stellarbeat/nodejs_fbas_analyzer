extern crate fbas_analyzer;

use neon::prelude::*;
use fbas_analyzer::{Fbas, NodeIdSetVecResult, NodeIdSetResult};
use fbas_analyzer::Analysis;
use hex;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;


fn analyze(mut cx: FunctionContext) -> JsResult<JsObject> {
    let nodes= cx.argument::<JsString>(0)?.value();
    //let failingNodes = cx.argument::<JsArray>(1)?.value();
    let fbas = Fbas::from_json_str(nodes.as_str());
    let fbas = fbas.to_standard_form();
    let fbas_hash = hex::encode(Sha3_256::digest(&fbas.to_json_string().into_bytes()));
    println!(
        "SHA3 hash of FBAS in standard form (when converted to JSON): {}",
        fbas_hash
    );


    // Now we only need to `do_analysis` when something significant changes in the quorum set
    // configuration!
    let mut results_cache: HashMap<Fbas, CustomResultsStruct> = HashMap::new();
    let analysis_results = if let Some(cached_results) = results_cache.get(&fbas) {
        println!("FBAS not updated, reuse results!");
        cached_results.clone()
    } else {
        println!("FBAS updated, running analysis");
        let new_results = do_analysis(&fbas);
        results_cache.insert(fbas.clone(), new_results.clone());
        new_results
    };

    //return object
    let object = JsObject::new(&mut cx);
    let has_quorum_intersection = cx.boolean(analysis_results.has_quorum_intersection);

    let minimal_blocking_sets = analysis_results.minimal_blocking_sets.clone().into_pretty_vec_vec(&fbas, None);
    let js_minimal_blocking_sets = JsArray::new(&mut cx, minimal_blocking_sets.len() as u32);
    for (i, minimal_blocking_set) in minimal_blocking_sets.iter().enumerate() {
        let js_minimal_blocking_set = JsArray::new(&mut cx, minimal_blocking_set.len() as u32);
        for (i,node_public_key) in minimal_blocking_set.iter().enumerate() {
            let js_node_public_key = cx.string(node_public_key);
            js_minimal_blocking_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
        }

        js_minimal_blocking_sets.set(&mut cx, i as u32, js_minimal_blocking_set).unwrap();
    }

    let minimal_splitting_sets = analysis_results.minimal_splitting_sets.clone().into_pretty_vec_vec(&fbas, None);
    let js_minimal_splitting_sets = JsArray::new(&mut cx, minimal_splitting_sets.len() as u32);
    for (i, minimal_splitting_set) in minimal_splitting_sets.iter().enumerate() {
        let js_minimal_splitting_set = JsArray::new(&mut cx, minimal_splitting_set.len() as u32);
        for (i,node_public_key) in minimal_splitting_set.iter().enumerate() {
            let js_node_public_key = cx.string(node_public_key);
            js_minimal_splitting_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
        }

        js_minimal_splitting_sets.set(&mut cx, i as u32, js_minimal_splitting_set).unwrap();
    }

    object.set(&mut cx, "hasQuorumIntersection", has_quorum_intersection).unwrap();
    object.set(&mut cx, "minimalBlockingSets", js_minimal_blocking_sets).unwrap();
    object.set(&mut cx, "minimalSplittingSets", js_minimal_splitting_sets).unwrap();

    Ok(object)
}

fn do_analysis(fbas: &Fbas) -> CustomResultsStruct {
    let analysis = Analysis::new(fbas);
    CustomResultsStruct {
        minimal_blocking_sets: analysis.minimal_blocking_sets(),
        minimal_splitting_sets: analysis.minimal_splitting_sets(),
        top_tier: analysis.top_tier(),
        has_quorum_intersection: analysis.has_quorum_intersection(),
    }
}

#[derive(Debug, Clone)]
struct CustomResultsStruct {
    minimal_blocking_sets: NodeIdSetVecResult,
    minimal_splitting_sets: NodeIdSetVecResult,
    top_tier: NodeIdSetResult,
    has_quorum_intersection: bool,
}

register_module!(mut cx, {
    cx.export_function("analyze", analyze)
});
