mod ldap;

use std::env;
use tokio;
use warp::Filter;

#[tokio::main]
async fn main() {
    match env::var("EXPORTER_PORT") {
        Ok(exporter_port_string) => {
            let exporter_port = exporter_port_string.parse::<u16>().unwrap();
            let routes = warp::path("metrics").and_then(|| async move {
                let body = match ldap::Ldap::go().await {
                    Ok(body) => body,
                    Err(_err) => return Err(warp::reject::not_found()),
                };
                Ok(format!("{}", body.as_str()))
            });
            warp::serve(routes).run(([0, 0, 0, 0], exporter_port)).await;
        }
        _ => println!("You must supply a port for the exporter to run on. EXPORTER_PORT=??"),
    }
}
