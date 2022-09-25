#[cfg(all(feature = "test_paths"))]
mod integration {
    use std::process::Command;

    use bitcoincore_rpc::{Auth, Client, RpcApi};

    #[test]
    fn test() {
        let compose_dir = format!("{}/tests/compose", env!("CARGO_MANIFEST_DIR"));
        println!("Running docker-compose at {}", compose_dir);
        Command::new("docker-compose")
            .arg("--project-directory")
            .arg(&compose_dir)
            .arg("up")
            .arg("-d")
            .output()
            .expect("failed to docker-compose ... up");

        // sanity check
        let rpc = Client::new(
            "http://localhost:43782",
            Auth::UserPass("ceiwHEbqWI83".to_string(), "DwubwWsoo3".to_string()),
        )
        .unwrap();
        assert!(rpc.get_best_block_hash().is_ok());

        
        Command::new("docker-compose")
            .arg("--project-directory")
            .arg(compose_dir)
            .arg("down")
            .output()
            .expect("failed to docker-compose ... down");
        assert!(true);
    }
}
