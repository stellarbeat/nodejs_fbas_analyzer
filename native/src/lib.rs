extern crate fbas_analyzer;

use neon::prelude::*;
use fbas_analyzer::Fbas;
use fbas_analyzer::Analysis;

fn analyze(mut cx: FunctionContext) -> JsResult<JsObject> {
    let nodes= cx.argument::<JsString>(0)?.value();
    let fbas = Fbas::from_json_str(nodes.as_str());
    let mut analysis = Analysis::new(&fbas, None);

    //return object
    let object = JsObject::new(&mut cx);
    let has_quorum_intersection = cx.boolean(analysis.has_quorum_intersection());
    object.set(&mut cx, "hasQuorumIntersection", has_quorum_intersection).unwrap();
    Ok(object)
}

register_module!(mut cx, {
    cx.export_function("analyze", analyze)
});
