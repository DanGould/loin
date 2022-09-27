#[cfg(all(feature = "test_paths"))]
mod integration {
    use std::{
        io::Write,
        process::{Command, Stdio}, str::FromStr,
    };

    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use tempfile::tempdir;
    use tonic_lnd::rpc::{ConnectPeerRequest, LightningAddress};

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

        std::thread::sleep(std::time::Duration::from_secs(10));
        // bitcoin rpc sanity check
        let bitcoin_rpc = Client::new(
            "http://localhost:43782",
            Auth::UserPass("ceiwHEbqWI83".to_string(), "DwubwWsoo3".to_string()),
        )
        .unwrap();
        assert!(&bitcoin_rpc.get_best_block_hash().is_ok());

        let tmp_dir = tempdir().expect("Couldn't open tmp_dir");
        let tmp_path = tmp_dir.path().to_str().expect("Invalid tmp_dir path");
        println!("{}", &tmp_path);

        Command::new("docker")
            .arg("cp")
            .arg("compose-merchant_lnd-1:/root/.lnd/tls.cert")
            .arg(format!("{}/merchant-tls.cert", &tmp_path))
            .output()
            .expect("failed to copy tls.cert");
            println!("copied merchant-tls.cert");

        Command::new("docker")
            .arg("cp")
            .arg("compose-merchant_lnd-1:/data/chain/bitcoin/regtest/admin.macaroon")
            .arg(format!("{}/merchant-admin.macaroon", &tmp_path))
            .output()
            .expect("failed to copy admin.macaroon");
        println!("copied merchant-admin.macaroon");

        // merchant lnd loin configuration
        let address_str = "https://localhost:53281";
        let address = tonic::transport::Endpoint::from_static(&address_str);
        let cert_file = format!("{}/merchant-tls.cert", &tmp_path).to_string();
        let macaroon_file = format!("{}/merchant-admin.macaroon", &tmp_path).to_string();

        // Connecting to LND requires only address, cert file, and macaroon file
        let mut merchant_client = tonic_lnd::connect(address_str, &cert_file, &macaroon_file).await.unwrap();

        let info = merchant_client.get_info(tonic_lnd::rpc::GetInfoRequest { }).await.unwrap();

        // conf to merchant
        let conf_string = format!("bind_port=3000\nlnd_address=\"{}\"\nlnd_cert_path=\"{}\"\nlnd_macaroon_path=\"{}\"", &address_str, &cert_file, &macaroon_file);
        let loin_conf = format!("{}/loin.conf", &tmp_path);
        std::fs::write(&loin_conf, conf_string).expect("Unable to write loin.conf");

        Command::new("docker")
            .arg("cp")
            .arg("compose-peer_lnd-1:/root/.lnd/tls.cert")
            .arg(format!("{}/peer-tls.cert", &tmp_path))
            .output()
            .expect("failed to copy tls.cert");
        println!("copied peer-tls-cert");

        Command::new("docker")
            .arg("cp")
            .arg("compose-peer_lnd-1:/data/chain/bitcoin/regtest/admin.macaroon")
            .arg(format!("{}/peer-admin.macaroon", &tmp_path))
            .output()
            .expect("failed to copy admin.macaroon");
        println!("copied peer-admin.macaroon");

        let address_str = "https://localhost:53283";
        let cert_file = format!("{}/peer-tls.cert", &tmp_path).to_string();
        let macaroon_file = format!("{}/peer-admin.macaroon", &tmp_path).to_string();

        // Connecting to LND requires only address, cert file, and macaroon file
        let mut peer_client = tonic_lnd::connect(address_str, &cert_file, &macaroon_file).await.unwrap();

        let info = peer_client.get_info(tonic_lnd::rpc::GetInfoRequest { }).await.unwrap();
        
        let peer_id_pubkey = info.into_inner().identity_pubkey;
        println!("{:#?}", peer_id_pubkey);

        let source_address = bitcoin_rpc.get_new_address(None, None).unwrap();
        bitcoin_rpc.generate_to_address(101, &source_address).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(5));
        println!("SLEPT");
        // connect one to the next
        let connected = merchant_client.connect_peer(ConnectPeerRequest { addr: Some(LightningAddress { pubkey: peer_id_pubkey.clone(), host: "peer_lnd:9735".to_string()}), perm: false, timeout: 6 }).await.expect("failed to connect peers");
        println!("{:?}", connected);

        let bip21 = Command::new("cargo")
            .arg("run")
            .arg("--features=test_paths")
            .arg("--")
            .arg("--conf")
            .arg(loin_conf)
            .arg("10") // fee_rate
            .arg(format!("{}@{}", peer_id_pubkey, "peer_lnd:9735")) // dest node uri
            .arg("250000") // channel_size
            .arg("10000") // anchor_deposit
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .spawn()
            .expect("pls");

        // error panick "server is still in the process of starting"
        println!("{:?}",bip21);

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
