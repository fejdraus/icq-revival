fn main() {
    // Embed typelib\flash.tlb as resource TYPELIB #1.
    println!("cargo:rerun-if-changed=typelib/flash.tlb");
    println!("cargo:rerun-if-changed=typelib/resource.rc");
    embed_resource::compile("typelib/resource.rc", embed_resource::NONE)
        .manifest_required()
        .unwrap();
}
