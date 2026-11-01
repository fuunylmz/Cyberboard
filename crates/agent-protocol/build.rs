fn main() {
    println!("cargo:rerun-if-changed=proto/agent.proto");
    tonic_build::configure()
        .compile_protos(&["proto/agent.proto", "proto/v2ray_api.proto"], &["proto"])
        .expect("compile agent protocol proto");
}
