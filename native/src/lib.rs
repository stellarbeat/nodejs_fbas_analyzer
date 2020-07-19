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

            let js_minimal_blocking_sets = vec_vec_to_js_array_array(&mut cx, analysis_result.minimal_blocking_sets.clone());
            let js_minimal_blocking_sets_faulty_nodes_filtered = vec_vec_to_js_array_array(&mut cx, analysis_result.minimal_blocking_sets_faulty_nodes_filtered.clone());

            let js_minimal_splitting_sets = vec_vec_to_js_array_array(&mut cx, analysis_result.minimal_splitting_sets.clone());
            let js_minimal_splitting_sets_faulty_nodes_filtered = vec_vec_to_js_array_array(&mut cx, analysis_result.minimal_splitting_sets_faulty_nodes_filtered.clone());

            let js_top_tier = vec_to_js_array(&mut cx, analysis_result.top_tier.clone());
            let js_top_tier_faulty_nodes_filtered = vec_to_js_array(&mut cx, analysis_result.top_tier_faulty_nodes_filtered.clone());

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

pub fn vec_to_js_array<'a, C: Context<'a>>(cx: &mut C, vec: Vec<String>) -> Handle<'a, JsArray> {
    let array = JsArray::new(cx, vec.len() as u32);
    for (i, string) in vec.iter().enumerate() {
        let js_string = cx.string(string);
        array.set( cx, i as u32, js_string).unwrap();
    }

    array
}


pub fn vec_vec_to_js_array_array<'a, C: Context<'a>>(cx: &mut C, vec_vec: Vec<Vec<String>>) -> Handle<'a, JsArray> {
    let array_array = JsArray::new(cx, vec_vec.len() as u32);
    for (i, vec) in vec_vec.iter().enumerate() {
        let array = vec_to_js_array(cx, vec.clone());
        array_array.set( cx, i as u32, array).unwrap();
    }

    array_array
}

register_module!(mut cx, {
    cx.export_class::<JsFbasAnalyzer>("FbasAnalyzer")?;
    Ok(())
});


