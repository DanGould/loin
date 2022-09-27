#[cfg(all(feature = "test_paths"))]
mod integration {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test() {
        let compose_dir = format!("{}/tests/compose", env!("CARGO_MANIFEST_DIR"));
        println!("Running docker-compose at {}", compose_dir);
        Command::new("docker-compose")
            .arg("--project-directory")
            .arg(&compose_dir)
            .arg("up")
            .arg("-d")
            .output()
            .expect("failed to docker-compose ... up");
        std::thread::sleep(std::time::Duration::from_secs(3));
        // bitcoin rpc sanity check
        let rpc = Client::new(
            "http://localhost:43782",
            Auth::UserPass("ceiwHEbqWI83".to_string(), "DwubwWsoo3".to_string()),
        )
        .unwrap();
        assert!(rpc.get_best_block_hash().is_ok());

        let tmp_dir = tempdir().expect("Couldn't open tmp_dir");
        let tmp_path = tmp_dir.path().to_str().expect("Invalid tmp_dir path");

        Command::new("docker")
            .arg("cp")
            .arg("compose-merchant_lnd-1:/root/.lnd/tls.cert")
            .arg(format!("{}/tls.cert", &tmp_path))
            .output()
            .expect("failed to copy tls.cert");

        Command::new("docker")
            .arg("cp")
            .arg("compose-merchant_lnd-1:/data/chain/bitcoin/regtest/admin.macaroon")
            .arg(format!("{}/admin.macaroon", &tmp_path))
            .output()
            .expect("failed to copy admin.macaroon");

        // merchant lnd rpc sanity check
        let address = "https://localhost:53281".to_string();
        let cert_file = format!("{}/tls.cert", &tmp_path).to_string();
        let macaroon_file = format!("{}/admin.macaroon", &tmp_path).to_string();

        // Connecting to LND requires only address, cert file, and macaroon file
        let mut client =
            tonic_lnd::connect(address, cert_file, macaroon_file).await.expect("failed to connect");

        Command::new("docker-compose")
            .arg("--project-directory")
            .arg(compose_dir)
            .arg("down")
            .output()
            .expect("failed to docker-compose ... down");
        assert!(true);

        tmp_dir.close().expect("Couldn't close tmp_dir");
    }
}
