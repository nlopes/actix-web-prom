use std::collections::HashMap;

use actix_web::dev::Service;
use actix_web::HttpMessage;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_web_prom::{PrometheusMetricsBuilder, MetricsConfig};


async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn get_posts_details() -> impl Responder {
    HttpResponse::Ok().json("some details")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut labels = HashMap::new();
    labels.insert("label1".to_string(), "value1".to_string());
    let prometheus = PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .const_labels(labels)
        .build()
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
            .service(web::resource("/health").to(health))
            .service(
                web::resource("/services/{service_id}")
                    .name("Services endpoint")
                    .wrap_fn(|req, srv| {
                        // example of a route where we want to keep the details of `service_id` param in the metrics
                        // we use a middleware to specify that `service_id` param values are kept in the labels
                        req.extensions_mut().insert::<MetricsConfig>(
                            MetricsConfig { cardinality_keep_params: vec!["service_id".to_string()] }
                        );
                        srv.call(req)
                    })
                    .route(web::get().to(get_posts_details))
            )
            .service(
                // example of a route where we want to ignore the cardinality of `post_id` in the metrics
                web::resource("/posts/{post_id}")
                    .name("Posts endpoint")
                    .route(web::get().to(get_posts_details))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;
    Ok(())
}

