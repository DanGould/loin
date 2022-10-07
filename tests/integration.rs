#[cfg(all(feature = "test_paths"))]
mod integration {
    use std::{
        env,
        io::BufWriter,
        process::{Command, Stdio}, thread::sleep,
    };

    use bip78::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
    use bip78::{PjUriExt, UriExt};
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use ln_types::P2PAddress;
    use loin::{scheduler::{ScheduledChannel, ScheduledPayJoin, Scheduler}, lnd::LndClient, http};
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use tempfile::tempdir;
    use tonic_lnd::rpc::{ConnectPeerRequest, LightningAddress};

    #[tokio::test]
    async fn test() -> Result<(), Box<dyn std::error::Error>> {
        let compose_dir = format!("{}/tests/compose", env!("CARGO_MANIFEST_DIR"));
        println!("Running docker-compose at {}", compose_dir);
        Command::new("docker-compose")
            .arg("--project-directory")
            .arg(&compose_dir)
            .arg("up")
            .arg("-d")
            .stdout(Stdio::piped())
            .output()
            .expect("failed to docker-compose ... up");

        // std::panic::set_hook(Box::new(|_| {
        //     println!("docker-compose down -v triggered from panic");
        //     let compose_dir = format!("{}/tests/compose", env!("CARGO_MANIFEST_DIR"));

        //     Command::new("docker-compose")
        //         .arg("--project-directory")
        //         .arg(compose_dir)
        //         .arg("down")
        //         .output()
        //         .expect("failed to docker-compose ... down");
        //     assert!(true);
        // }));

        let tmp_dir = tempdir().expect("Couldn't open tmp_dir");
        let tmp_path = tmp_dir.path().to_str().expect("Invalid tmp_dir path");
        println!("{}", &tmp_path);

        std::thread::sleep(std::time::Duration::from_secs(10));
        // bitcoin rpc sanity check
        let bitcoin_rpc = Client::new(
            "http://localhost:43782",
            Auth::UserPass("ceiwHEbqWI83".to_string(), "DwubwWsoo3".to_string()),
        )
        .unwrap();
        assert!(&bitcoin_rpc.get_best_block_hash().is_ok());

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

        let paths = std::fs::read_dir(&tmp_path).unwrap();

        for path in paths {
            println!("Name: {}", path.unwrap().path().display())
        }

        // merchant lnd loin configuration
        let address_str = "https://localhost:53281";
        let cert_file = format!("{}/merchant-tls.cert", &tmp_path).to_string();
        let macaroon_file = format!("{}/merchant-admin.macaroon", &tmp_path).to_string();

        // Connecting to LND requires only address, cert file, and macaroon file
        let mut merchant_client =
            tonic_lnd::connect(address_str, &cert_file, &macaroon_file).await.unwrap();

        // Just test the node rpc
        merchant_client.get_info(tonic_lnd::rpc::GetInfoRequest {}).await.unwrap();

        // conf to merchant
        let conf_string = format!(
            "bind_port=3000\nlnd_address=\"{}\"\nlnd_cert_path=\"{}\"\nlnd_macaroon_path=\"{}\"",
            &address_str, &cert_file, &macaroon_file
        );
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
        let mut peer_client =
            tonic_lnd::connect(address_str, &cert_file, &macaroon_file).await.unwrap();

        let info = peer_client.get_info(tonic_lnd::rpc::GetInfoRequest {}).await.unwrap();

        let peer_id_pubkey = info.into_inner().identity_pubkey;
        println!("peer_id_pubkey: {:#?}", peer_id_pubkey);

        let source_address = bitcoin_rpc.get_new_address(None, None).unwrap();
        bitcoin_rpc.generate_to_address(101, &source_address).unwrap();
        // bitcoin-cli -chain=regtest -rpcport=43782 -rpcpassword=DwubwWsoo3 -rpcuser=ceiwHEbqWI83 -generate 100
        std::thread::sleep(std::time::Duration::from_secs(5));
        println!("SLEPT");
        // connect one to the next
        let connected = merchant_client
            .connect_peer(ConnectPeerRequest {
                addr: Some(LightningAddress {
                    pubkey: peer_id_pubkey.clone(),
                    host: "peer_lnd:9735".to_string(),
                }),
                perm: false,
                timeout: 6,
            })
            .await
            .expect("failed to connect peers");
        println!("{:?}", connected);

        let peer_address = format!("{}@{}", peer_id_pubkey, "peer_lnd:9735");
        let peer_address = peer_address.parse::<P2PAddress>().expect("invalid ln P2PAddress");

        let channel_capacity = bitcoin::Amount::from_sat(250000);

        let fee_rate = 1;
        let mut channels = Vec::with_capacity(1);
        let wallet_amount = bitcoin::Amount::from_sat(10000);
        channels.push(ScheduledChannel::new(peer_address, channel_capacity));
        let pj = ScheduledPayJoin::new(wallet_amount, channels, fee_rate);
        let scheduler = Scheduler::new(LndClient::new(merchant_client).await.unwrap());
        let address = scheduler.schedule_payjoin(&pj).await.unwrap();

        let bip21 = format!(
            "bitcoin:{}?amount={}&pj=https://localhost:3010/pj",
            address,
            pj.total_amount().to_string_in(bitcoin::Denomination::Bitcoin)
        );
        println!("{}", &bip21);

        let bind_addr = ([127, 0, 0, 1], 3000).into();
        // trigger payjoin-client
        tokio::spawn(async move {
            std::thread::sleep(std::time::Duration::from_secs(2));
            println!("2 sec after");
            Command::new("curl")
                .arg("http://localhost:3000/pj/static/index.html")
                .stdout(Stdio::piped())
                .output()
                .expect("curl'd brah");

            Command::new("curl")
                .arg("https://localhost:3010/pj/static/index.html")
                .stdout(Stdio::piped())
                .output()
                .expect("curl'd brah");

            let link = bip78::Uri::try_from(bip21).expect("bad bip78 uri");

            let link = link
                .check_pj_supported()
                .unwrap_or_else(|_| panic!("The provided URI doesn't support payjoin (BIP78)"));

            if link.amount.is_none() {
                panic!("please specify the amount in the Uri");
            }

            let mut outputs = HashMap::with_capacity(1);
            outputs.insert(link.address.to_string(), link.amount.expect("bad bip78 uri amount"));

            let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
                lock_unspent: Some(true),
                fee_rate: Some(bip78::bitcoin::Amount::from_sat(2000)),
                ..Default::default()
            };
            let psbt = bitcoin_rpc
                .wallet_create_funded_psbt(
                    &[], // inputs
                    &outputs,
                    None, // locktime
                    Some(options),
                    None,
                )
                .expect("failed to create PSBT")
                .psbt;
            let psbt = bitcoin_rpc.wallet_process_psbt(&psbt, None, None, None).expect("bitcoind failed to fund psbt").psbt;
            let psbt = load_psbt_from_base64(psbt.as_bytes()).expect("bad psbt bytes");
            println!("Original psbt: {:#?}", psbt);
            let pj_params = bip78::sender::Configuration::with_fee_contribution(
                bip78::bitcoin::Amount::from_sat(10000),
                None,
            );
            let (req, ctx) = link.create_pj_request(psbt, pj_params).expect("failed to make http pj request");
            let url = req.url.to_string().parse::<hyper::Uri>().unwrap();
            let request = hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri(url)
                .header("Content-Type", "text/plain")
                .body(hyper::Body::from(req.body))
                .expect("request builder");
            println!("request: {:?}", request);
            let https = hyper_tls::HttpsConnector::new();
            let client = hyper::Client::builder()
                .build::<_, hyper::Body>(https);
            let response = client.request(request).await.expect("failed to get http pj response");
            println!("res: {:#?}", response);
            let response = hyper::body::to_bytes(response.into_body()).await.expect("failed to deserialize response");
            println!("res: {:#?}", response);

            // let response = reqwest::blocking::Client::new()
            //     .post(req.url)
            //     .body(req.body)
            //     .header("Content-Type", "text/plain")
            //     .send()
            //     .expect("failed to communicate");
            //.error_for_status()
            //.unwrap();
            let psbt = ctx.process_response(response.to_vec().as_slice()).expect("failed to process response");
            println!("Proposed psbt: {:#?}", psbt);
            let psbt =
            bitcoin_rpc.wallet_process_psbt(&serialize_psbt(&psbt), None, None, None).unwrap().psbt;
            let tx = bitcoin_rpc.finalize_psbt(&psbt, Some(true)).unwrap().hex.expect("incomplete psbt");
            bitcoin_rpc.send_raw_transaction(&tx).unwrap();
        }).await?;

        http::serve(scheduler, bind_addr).await?;

        std::thread::sleep(std::time::Duration::from_secs(20));
        println!("going down");
        Command::new("docker-compose")
            .arg("--project-directory")
            .arg(&compose_dir)
            .arg("down")
            .output()
            .expect("failed to docker-compose ... down");
        assert!(true);

        tmp_dir.close().expect("Couldn't close tmp_dir");
        Ok(())
    }

    fn load_psbt_from_base64(
        mut input: impl std::io::Read,
    ) -> Result<Psbt, bip78::bitcoin::consensus::encode::Error> {
        use bip78::bitcoin::consensus::Decodable;

        let reader = base64::read::DecoderReader::new(
            &mut input,
            base64::Config::new(base64::CharacterSet::Standard, true),
        );
        Psbt::consensus_decode(reader)
    }

    fn serialize_psbt(psbt: &Psbt) -> String {
        use bip78::bitcoin::consensus::Encodable;

        let mut encoder = base64::write::EncoderWriter::new(Vec::new(), base64::STANDARD);
        psbt.consensus_encode(&mut encoder)
            .expect("Vec doesn't return errors in its write implementation");
        String::from_utf8(
            encoder.finish().expect("Vec doesn't return errors in its write implementation"),
        )
        .unwrap()
    }
}
