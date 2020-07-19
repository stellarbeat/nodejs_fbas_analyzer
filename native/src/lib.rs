extern crate fbas_analyzer;

use neon::prelude::*;
use fbas_analyzer::{Fbas, NodeIdSetVecResult, NodeIdSetResult};
use fbas_analyzer::Analysis;
use std::collections::HashMap;

pub type PublicKey = String;

pub struct FbasAnalyzer {
    results_cache: HashMap<Fbas, AnalysisResult>,
}

impl FbasAnalyzer {
    fn new() -> FbasAnalyzer {
        FbasAnalyzer {
            results_cache: HashMap::new()
        }
    }

    pub fn analyze<'a>(&mut self, nodes: String, faulty_nodes: &[&'a str]) -> AnalysisResultFull {
        //let failingNodes = cx.argument::<JsArray>(1)?.value();
        let fbas = Fbas::from_json_str(nodes.as_str());
        let fbas = fbas.to_standard_form();

        // Now we only need to `do_analysis` when something significant changes in the quorum set
        // configuration!
        let mut cache_hit = false;
        let analysis_results = if let Some(cached_results) = self.results_cache.get(&fbas) {
            println!("FBAS not updated, reuse results!");
            cache_hit = true;
            cached_results.clone()
        } else {
            println!("FBAS updated, running analysis");
            let new_results = FbasAnalyzer::do_analysis(&fbas);
            self.results_cache.insert(fbas.clone(), new_results.clone());
            new_results
        };

        let _has_quorum_intersection = analysis_results.has_quorum_intersection;

        let minimal_blocking_sets_faulty_nodes_filtered = analysis_results.minimal_blocking_sets
            .without_nodes_pretty(&faulty_nodes, &fbas, None)
            .minimal_sets();
        let minimal_splitting_sets_faulty_nodes_filtered = analysis_results.minimal_splitting_sets
            .without_nodes_pretty(&faulty_nodes, &fbas, None)
            .minimal_sets();
        let top_tier_faulty_nodes_filtered = analysis_results.top_tier.without_nodes_pretty(&faulty_nodes, &fbas, None);

        AnalysisResultFull {
            minimal_blocking_sets: analysis_results.minimal_blocking_sets.clone().into_pretty_vec_vec(&fbas, None),
            minimal_splitting_sets: analysis_results.minimal_splitting_sets.clone().into_pretty_vec_vec(&fbas, None),
            top_tier: analysis_results.top_tier.clone().into_pretty_vec(&fbas, None),
            has_quorum_intersection: analysis_results.has_quorum_intersection,
            minimal_blocking_sets_faulty_nodes_filtered: minimal_blocking_sets_faulty_nodes_filtered.clone().into_pretty_vec_vec(&fbas, None),
            minimal_splitting_sets_faulty_nodes_filtered: minimal_splitting_sets_faulty_nodes_filtered.clone().into_pretty_vec_vec(&fbas, None),
            has_quorum_intersection_faulty_nodes_filtered: !minimal_splitting_sets_faulty_nodes_filtered.contains_empty_set(),
            top_tier_faulty_nodes_filtered: top_tier_faulty_nodes_filtered.clone().into_pretty_vec(&fbas, None),
            cache_hit,
        }
    }

    fn do_analysis(fbas: &Fbas) -> AnalysisResult {
        let analysis = Analysis::new(fbas);
        AnalysisResult {
            minimal_blocking_sets: analysis.minimal_blocking_sets(),
            minimal_splitting_sets: analysis.minimal_splitting_sets(),
            top_tier: analysis.top_tier(),
            has_quorum_intersection: analysis.has_quorum_intersection(),
        }
    }
}

#[derive(Debug, Clone)]
struct AnalysisResult {
    minimal_blocking_sets: NodeIdSetVecResult,
    minimal_splitting_sets: NodeIdSetVecResult,
    top_tier: NodeIdSetResult,
    has_quorum_intersection: bool,
}

pub struct AnalysisResultFull {
    minimal_blocking_sets: Vec<Vec<PublicKey>>,
    minimal_splitting_sets: Vec<Vec<PublicKey>>,
    top_tier: Vec<PublicKey>,
    top_tier_faulty_nodes_filtered: Vec<PublicKey>,
    has_quorum_intersection: bool,
    minimal_blocking_sets_faulty_nodes_filtered: Vec<Vec<PublicKey>>,
    minimal_splitting_sets_faulty_nodes_filtered: Vec<Vec<PublicKey>>,
    has_quorum_intersection_faulty_nodes_filtered: bool,
    cache_hit: bool,
}

/**
* NEON (javascript mapping) CODE BELOW
*/
declare_types! {
    pub class JsFbasAnalyzer for FbasAnalyzer {

        init(mut _cx) {
            Ok(FbasAnalyzer::new())
        }

        method analyze(mut cx) {
            let mut this = cx.this();
            let nodes = cx.argument::<JsString>(0)?.value();

            let analysis_result = {
                let guard = cx.lock();
                let mut fbas_analyzer = this.borrow_mut(&guard);

                fbas_analyzer.analyze(nodes, &vec![])
            };

            let js_analysis_result = JsObject::new(&mut cx);

            let js_cache_hit = cx.boolean(analysis_result.cache_hit);
            let js_has_quorum_intersection = cx.boolean(analysis_result.has_quorum_intersection);
            let js_has_quorum_intersection_faulty_nodes_filtered = cx.boolean(analysis_result.has_quorum_intersection_faulty_nodes_filtered);

            let js_minimal_blocking_sets = JsArray::new(&mut cx, analysis_result.minimal_blocking_sets.len() as u32);
            for (i, minimal_blocking_set) in analysis_result.minimal_blocking_sets.iter().enumerate() {
                let js_minimal_blocking_set = JsArray::new(&mut cx, minimal_blocking_set.len() as u32);
                for (i, node_public_key) in minimal_blocking_set.iter().enumerate() {
                    let js_node_public_key = cx.string(node_public_key);
                    js_minimal_blocking_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
                }
                js_minimal_blocking_sets.set(&mut cx, i as u32, js_minimal_blocking_set).unwrap();
            }

            let js_minimal_blocking_sets_faulty_nodes_filtered = JsArray::new(&mut cx, analysis_result.minimal_blocking_sets_faulty_nodes_filtered.len() as u32);
            for (i, minimal_blocking_set) in analysis_result.minimal_blocking_sets.iter().enumerate() {
                let js_minimal_blocking_set = JsArray::new(&mut cx, minimal_blocking_set.len() as u32);
                for (i, node_public_key) in minimal_blocking_set.iter().enumerate() {
                    let js_node_public_key = cx.string(node_public_key);
                    js_minimal_blocking_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
                }
                js_minimal_blocking_sets_faulty_nodes_filtered.set(&mut cx, i as u32, js_minimal_blocking_set).unwrap();
            }

            let js_minimal_splitting_sets = JsArray::new(&mut cx, analysis_result.minimal_splitting_sets.len() as u32);
            for (i, minimal_splitting_set) in analysis_result.minimal_splitting_sets.iter().enumerate() {
                let js_minimal_splitting_set = JsArray::new(&mut cx, minimal_splitting_set.len() as u32);
                for (i, node_public_key) in minimal_splitting_set.iter().enumerate() {
                    let js_node_public_key = cx.string(node_public_key);
                    js_minimal_splitting_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
                }
                js_minimal_splitting_sets.set(&mut cx, i as u32, js_minimal_splitting_set).unwrap();
            }

            let js_minimal_splitting_sets_faulty_nodes_filtered = JsArray::new(&mut cx, analysis_result.minimal_splitting_sets_faulty_nodes_filtered.len() as u32);
            for (i, minimal_splitting_set) in analysis_result.minimal_splitting_sets_faulty_nodes_filtered.iter().enumerate() {
                let js_minimal_splitting_set = JsArray::new(&mut cx, minimal_splitting_set.len() as u32);
                for (i, node_public_key) in minimal_splitting_set.iter().enumerate() {
                    let js_node_public_key = cx.string(node_public_key);
                    js_minimal_splitting_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
                }
                js_minimal_splitting_sets_faulty_nodes_filtered.set(&mut cx, i as u32, js_minimal_splitting_set).unwrap();
            }

            let js_top_tier = JsArray::new(&mut cx, analysis_result.top_tier.len() as u32);
            for (i, node_public_key) in analysis_result.top_tier.iter().enumerate() {
                    let js_node_public_key = cx.string(node_public_key);
                    js_top_tier.set(&mut cx, i as u32, js_node_public_key).unwrap();
            }

            let js_top_tier_faulty_nodes_filtered = JsArray::new(&mut cx, analysis_result.top_tier_faulty_nodes_filtered.len() as u32);
            for (i, node_public_key) in analysis_result.top_tier_faulty_nodes_filtered.iter().enumerate() {
                    let js_node_public_key = cx.string(node_public_key);
                    js_top_tier_faulty_nodes_filtered.set(&mut cx, i as u32, js_node_public_key).unwrap();
            }

            js_analysis_result.set(&mut cx, "cache_hit", js_cache_hit).unwrap();
            js_analysis_result.set(&mut cx, "has_quorum_intersection", js_has_quorum_intersection).unwrap();
            js_analysis_result.set(&mut cx, "has_quorum_intersection_faulty_nodes_filtered", js_has_quorum_intersection_faulty_nodes_filtered).unwrap();
            js_analysis_result.set(&mut cx, "minimal_blocking_sets", js_minimal_blocking_sets).unwrap();
            js_analysis_result.set(&mut cx, "minimal_blocking_sets_faulty_nodes_filtered", js_minimal_blocking_sets_faulty_nodes_filtered).unwrap();
            js_analysis_result.set(&mut cx, "minimal_splitting_sets", js_minimal_splitting_sets).unwrap();
            js_analysis_result.set(&mut cx, "minimal_splitting_sets_faulty_nodes_filtered", js_minimal_splitting_sets_faulty_nodes_filtered).unwrap();
            js_analysis_result.set(&mut cx, "top_tier", js_top_tier).unwrap();
            js_analysis_result.set(&mut cx, "top_tier_faulty_nodes_filtered", js_top_tier_faulty_nodes_filtered).unwrap();
            Ok(js_analysis_result.upcast())
        }
    }
}

register_module!(mut cx, {
    cx.export_class::<JsFbasAnalyzer>("FbasAnalyzer")?;
    Ok(())
});

/*pub fn analyze(mut cx: FunctionContext) -> JsResult<JsObject> {
    let nodes = cx.argument::<JsString>(0)?.value();
    //let failingNodes = cx.argument::<JsArray>(1)?.value();
    let fbas = Fbas::from_json_str(nodes.as_str());
    let fbas = fbas.to_standard_form();
    let fbas_hash = hex::encode(Sha3_256::digest(&fbas.to_json_string().into_bytes()));
    println!(
        "SHA3 hash of FBAS in standard form (when converted to JSON): {}",
        fbas_hash
    );

    //'javascript' object returned to nodejs
    let js_analysis_results = JsObject::new(&mut cx);
    let mut results_cache: HashMap<Fbas, CustomResultsStruct> = HashMap::new();
    // Now we only need to `do_analysis` when something significant changes in the quorum set
    // configuration!
    let mut is_cached = false;
    let analysis_results = if let Some(cached_results) = results_cache.get(&fbas) {
        println!("FBAS not updated, reuse results!");
        is_cached = true;
        cached_results.clone()
    } else {
        println!("FBAS updated, running analysis");
        let new_results = do_analysis_meh(&fbas);
        results_cache.insert(fbas.clone(), new_results.clone());
        new_results
    };
    let js_is_cached = cx.boolean(is_cached);
    js_analysis_results.set(&mut cx, "isCached", js_is_cached).unwrap();

    let has_quorum_intersection = cx.boolean(analysis_results.has_quorum_intersection);

    let minimal_blocking_sets = analysis_results.minimal_blocking_sets.clone().into_pretty_vec_vec(&fbas, None);
    let js_minimal_blocking_sets = JsArray::new(&mut cx, minimal_blocking_sets.len() as u32);
    for (i, minimal_blocking_set) in minimal_blocking_sets.iter().enumerate() {
        let js_minimal_blocking_set = JsArray::new(&mut cx, minimal_blocking_set.len() as u32);
        for (i, node_public_key) in minimal_blocking_set.iter().enumerate() {
            let js_node_public_key = cx.string(node_public_key);
            js_minimal_blocking_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
        }

        js_minimal_blocking_sets.set(&mut cx, i as u32, js_minimal_blocking_set).unwrap();
    }

    let minimal_splitting_sets = analysis_results.minimal_splitting_sets.clone().into_pretty_vec_vec(&fbas, None);
    let js_minimal_splitting_sets = JsArray::new(&mut cx, minimal_splitting_sets.len() as u32);
    for (i, minimal_splitting_set) in minimal_splitting_sets.iter().enumerate() {
        let js_minimal_splitting_set = JsArray::new(&mut cx, minimal_splitting_set.len() as u32);
        for (i, node_public_key) in minimal_splitting_set.iter().enumerate() {
            let js_node_public_key = cx.string(node_public_key);
            js_minimal_splitting_set.set(&mut cx, i as u32, js_node_public_key).unwrap();
        }

        js_minimal_splitting_sets.set(&mut cx, i as u32, js_minimal_splitting_set).unwrap();
    }

    js_analysis_results.set(&mut cx, "hasQuorumIntersection", has_quorum_intersection).unwrap();
    js_analysis_results.set(&mut cx, "minimalBlockingSets", js_minimal_blocking_sets).unwrap();
    js_analysis_results.set(&mut cx, "minimalSplittingSets", js_minimal_splitting_sets).unwrap();

    Ok(js_analysis_results)
}*/


