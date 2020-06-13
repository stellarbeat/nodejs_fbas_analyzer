extern crate fbas_analyzer;

use neon::prelude::*;
use fbas_analyzer::Fbas;
use fbas_analyzer::Analysis;

fn analyze(mut cx: FunctionContext) -> JsResult<JsObject> {
    let nodes= cx.argument::<JsString>(0)?.value();
    let fbas = Fbas::from_json_str(nodes.as_str());
    let analysis = Analysis::new(&fbas, None);

    //return object
    let object = JsObject::new(&mut cx);
    let has_quorum_intersection = cx.boolean(analysis.has_quorum_intersection());

    let minimal_blocking_sets = analysis.minimal_blocking_sets().into_vec_vec();
    let js_minimal_blocking_sets = JsArray::new(&mut cx, minimal_blocking_sets.len() as u32);
    for (i, minimal_blocking_set) in minimal_blocking_sets.iter().enumerate() {
        let js_minimal_blocking_set = JsArray::new(&mut cx, minimal_blocking_set.len() as u32);
        for (i,node_id) in minimal_blocking_set.iter().enumerate() {
            let js_node_id = cx.number(*node_id as f64);
            js_minimal_blocking_set.set(&mut cx, i as u32, js_node_id).unwrap();
        }

        js_minimal_blocking_sets.set(&mut cx, i as u32, js_minimal_blocking_set).unwrap();
    }

    let minimal_splitting_sets = analysis.minimal_splitting_sets().into_vec_vec();
    let js_minimal_splitting_sets = JsArray::new(&mut cx, minimal_splitting_sets.len() as u32);
    for (i, minimal_splitting_set) in minimal_splitting_sets.iter().enumerate() {
        let js_minimal_splitting_set = JsArray::new(&mut cx, minimal_splitting_set.len() as u32);
        for (i,node_id) in minimal_splitting_set.iter().enumerate() {
            let js_node_id = cx.number(*node_id as f64);
            js_minimal_splitting_set.set(&mut cx, i as u32, js_node_id).unwrap();
        }

        js_minimal_splitting_sets.set(&mut cx, i as u32, js_minimal_splitting_set).unwrap();
    }

    object.set(&mut cx, "hasQuorumIntersection", has_quorum_intersection).unwrap();
    object.set(&mut cx, "minimalBlockingSets", js_minimal_blocking_sets).unwrap();
    object.set(&mut cx, "minimalSplittingSets", js_minimal_splitting_sets).unwrap();

    Ok(object)
}

register_module!(mut cx, {
    cx.export_function("analyze", analyze)
});
