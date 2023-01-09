use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetricsBuilder;
use prometheus::{opts, IntCounterVec};

async fn health(counter: web::Data<IntCounterVec>) -> HttpResponse {
    counter
        .with_label_values(&["endpoint", "method", "status"])
        .inc();
    HttpResponse::Ok().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let prometheus = PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .build()
        .unwrap();

    let counter_opts = opts!("counter", "some random counter").namespace("api");
    let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();
    prometheus
        .registry
        .as_ref()
        .register(Box::new(counter.clone()))
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
            .app_data(web::Data::new(counter.clone()))
            .service(web::resource("/health").to(health))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;
    Ok(())
}
