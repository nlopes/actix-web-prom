use actix_web::rt::System;
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetricsBuilder;
use prometheus::Registry;
use std::thread;

async fn public_handler() -> HttpResponse {
    HttpResponse::Ok().body("Everyone can see it!")
}

async fn private_handler() -> HttpResponse {
    HttpResponse::Ok().body("This can be hidden behind a firewall")
}

fn main() -> std::io::Result<()> {
    let shared_registry = Registry::new();

    let private_metrics = PrometheusMetricsBuilder::new("private_api")
        .registry(shared_registry.clone())
        .endpoint("/metrics")
        .build()
        // It is safe to unwrap when __no other app has the same namespace__
        .unwrap();

    let public_metrics = PrometheusMetricsBuilder::new("public_api")
        .registry(shared_registry)
        // Metrics should not be available from the outside
        // so no endpoint is registered
        .build()
        .unwrap();

    let private_thread = thread::spawn(move || {
        let sys = System::new();
        let srv = HttpServer::new(move || {
            App::new()
                .wrap(private_metrics.clone())
                .service(web::resource("/test").to(private_handler))
        })
        .bind("127.0.0.1:8081")
        .unwrap()
        .run();
        sys.block_on(srv).unwrap();
    });

    let public_thread = thread::spawn(|| {
        let sys = System::new();
        let srv = HttpServer::new(move || {
            App::new()
                .wrap(public_metrics.clone())
                .service(web::resource("/test").to(public_handler))
        })
        .bind("127.0.0.1:8082")
        .unwrap()
        .run();
        sys.block_on(srv).unwrap();
    });

    private_thread.join().unwrap();
    public_thread.join().unwrap();
    Ok(())
}
