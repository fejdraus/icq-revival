fn main() {
    // The version resource lets the ICQ 7.2 patch tell our tbdiag.dll from the
    // stock AOL Diagnostics module by its ProductName and InternalName.
    println!("cargo:rerun-if-changed=resource.rc");
    embed_resource::compile("resource.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
