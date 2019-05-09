# Prometheus middleware for actix-web

[![Build Status](https://travis-ci.org/nlopes/actix-web-prom.svg?branch=master)](https://travis-ci.org/nlopes/actix-web-prom)
[![docs.rs](https://docs.rs/actix-web-prom/badge.svg)](https://docs.rs/actix-web-prom)
[![crates.io](https://img.shields.io/crates/v/actix-web-prom.svg)](https://crates.io/crates/actix-web-prom)

Prometheus instrumentation for [actix-web](https://github.com/actix/actix-web). This
middleware is heavily influenced by the work in
[sd2k/rocket_prometheus](https://github.com/sd2k/rocket_prometheus). We track the same
default metrics and allow for adding user defined metrics.

By default two metrics are tracked (this assumes the namespace `actix_web_prom`):

  - `actix_web_prom_http_requests_total` (labels: endpoint, method, status): the total number
   of HTTP requests handled by the actix HttpServer.

  - `actix_web_prom_http_requests_duration_seconds` (labels: endpoint, method, status): the
   request duration for all HTTP requests handled by the actix HttpServer.


## Usage

First add `actix_web_prom` to your `Cargo.toml`:

```toml
[dependencies]
actix_web_prom = "0.1"
```

You then instantiate the prometheus middleware and pass it to `.wrap()`:

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetrics;

fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn main() -> std::io::Result<()> {
    let prometheus = PrometheusMetrics::new("api", "/metrics");
    HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
            .service(web::resource("/health").to(health))
    })
    .bind("127.0.0.1:8080")?
    .run();
    Ok(())
}
```

Using the above as an example, a few things are worth mentioning:
 - `api` is the metrics namespace
 - `/metrics` will be auto exposed (GET requests only)

A call to the /metrics endpoint will expose your metrics:

```shell
$ curl http://localhost:8080/metrics
# HELP api_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE api_http_requests_duration_seconds histogram
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.005"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.01"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.025"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.05"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.25"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="2.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="10"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="+Inf"} 1
api_http_requests_duration_seconds_sum{endpoint="/metrics",method="GET",status="200"} 0.00003
api_http_requests_duration_seconds_count{endpoint="/metrics",method="GET",status="200"} 1
# HELP api_http_requests_total Total number of HTTP requests
# TYPE api_http_requests_total counter
api_http_requests_total{endpoint="/metrics",method="GET",status="200"} 1
```

## Custom metrics

You instantiate `PrometheusMetrics` and then use its `.registry` to register your custom
metric (in this case, we use a `IntCounterVec`.

Then you can pass this counter through `.data()` to have it available within the resource
responder.

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetrics;
use prometheus::IntCounterVec;

fn health(counter: web::Data<IntCounterVec>) -> HttpResponse {
    counter.with_label_values(&["endpoint", "method", "status"]).inc();
    HttpResponse::Ok().finish()
}

fn main() -> std::io::Result<()> {
    let prometheus = PrometheusMetrics::new("api", "/metrics");

    let counter_opts = opts!("counter", "some random counter").namespace("api");
    let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();
    prometheus
        .registry
        .register(Box::new(counter.clone()))
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
            .data(counter.clone())
            .service(web::resource("/health").to(health))
    })
    .bind("127.0.0.1:8080")?
    .run();
    Ok(())
}
```
