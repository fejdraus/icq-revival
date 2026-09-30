use std::path::Path;

fn main() {
    // Force the exact, undecorated export names the client imports (a .def keeps
    // stdcall names from being decorated on i686).
    let def = Path::new(env!("CARGO_MANIFEST_DIR")).join("msimg32.def");
    println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def.display());
    println!("cargo:rerun-if-changed=msimg32.def");

    // Version resource, so the DLL is identifiable in Explorer.
    println!("cargo:rerun-if-changed=resource.rc");
    embed_resource::compile("resource.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
