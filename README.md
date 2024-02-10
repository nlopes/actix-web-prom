# actix-web-prom

[![CI Status](https://github.com/nlopes/actix-web-prom/workflows/Test/badge.svg)](https://github.com/nlopes/actix-web-prom/actions)
[![docs.rs](https://docs.rs/actix-web-prom/badge.svg)](https://docs.rs/actix-web-prom)
[![crates.io](https://img.shields.io/crates/v/actix-web-prom.svg)](https://crates.io/crates/actix-web-prom)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/nlopes/actix-web-prom/blob/master/LICENSE)

Prometheus instrumentation for [actix-web](https://github.com/actix/actix-web). This middleware is heavily influenced by the work in [sd2k/rocket_prometheus](https://github.com/sd2k/rocket_prometheus). We track the same default metrics and allow for adding user defined metrics.

By default two metrics are tracked (this assumes the namespace `actix_web_prom`):

  - `actix_web_prom_http_requests_total` (labels: endpoint, method, status): the total number
   of HTTP requests handled by the actix HttpServer.

  - `actix_web_prom_http_requests_duration_seconds` (labels: endpoint, method, status): the
   request duration for all HTTP requests handled by the actix HttpServer.


## Usage

First add `actix-web-prom` to your `Cargo.toml`:

```toml
[dependencies]
actix-web-prom = "0.8.0"
```

You then instantiate the prometheus middleware and pass it to `.wrap()`:

```rust
use std::collections::HashMap;

use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
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
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?;
    Ok(())
}
```

Using the above as an example, a few things are worth mentioning:
 - `api` is the metrics namespace
 - `/metrics` will be auto exposed (GET requests only) with Content-Type header `content-type: text/plain; version=0.0.4; charset=utf-8`
 - `Some(labels)` is used to add fixed labels to the metrics; `None` can be passed instead
  if no additional labels are necessary.


A call to the /metrics endpoint will expose your metrics:

```shell
$ curl http://localhost:8080/metrics
# HELP api_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE api_http_requests_duration_seconds histogram
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.005"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.01"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.025"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.05"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.25"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="2.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="10"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="+Inf"} 1
api_http_requests_duration_seconds_sum{endpoint="/metrics",label1="value1",method="GET",status="200"} 0.00003
api_http_requests_duration_seconds_count{endpoint="/metrics",label1="value1",method="GET",status="200"} 1
# HELP api_http_requests_total Total number of HTTP requests
# TYPE api_http_requests_total counter
api_http_requests_total{endpoint="/metrics",label1="value1",method="GET",status="200"} 1
```

### Features
If you enable `process` feature of this crate, default process metrics will also be collected.
[Default process metrics](https://prometheus.io/docs/instrumenting/writing_clientlibs/#process-metrics)

```shell
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0.22
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1048576
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 78
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 17526784
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1628105774.92
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 1893163008
```

### Custom metrics

You instantiate `PrometheusMetrics` and then use its `.registry` to register your custom
metric (in this case, we use a `IntCounterVec`).

Then you can pass this counter through `.data()` to have it available within the resource
responder.

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};
use prometheus::{opts, IntCounterVec};

async fn health(counter: web::Data<IntCounterVec>) -> HttpResponse {
    counter.with_label_values(&["endpoint", "method", "status"]).inc();
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
        .register(Box::new(counter.clone()))
        .unwrap();

        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .data(counter.clone())
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?;
    Ok(())
}
```

### Custom `Registry`

Some apps might have more than one `actix_web::HttpServer`.
If that's the case, you might want to use your own registry:

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};
use actix_web::rt::System;
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
        .registry(shared_registry.clone())
        // Metrics should not be available from the outside
        // so no endpoint is registered
        .build()
        .unwrap();

    let private_thread = thread::spawn(move || {
        let mut sys = System::new();
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
        let mut sys = System::new();
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

```

### Configurable routes pattern cardinality

Let's say you have on your app a route to fetch posts by language and by slug `GET /posts/{language}/{slug}`.
By default, actix-web-prom will provide metrics for the whole route with the label `endpoint` set to the pattern `/posts/{language}/{slug}`.
This is great but you cannot differentiate metrics across languages (as there is only a limited set of them).
Actix-web-prom can be configured to allow for more cardinality on some route params.

For that you need to add a middleware to pass some [extensions data](https://blog.adamchalmers.com/what-are-extensions/), specifically the `MetricsConfig` struct that contains the list of params you want to keep cardinality on.

```rust
use actix_web::dev::Service;
use actix_web::HttpMessage;
use actix_web_prom::MetricsConfig;

web::resource("/posts/{language}/{slug}")
    .wrap_fn(|req, srv| {
        req.extensions_mut().insert::<MetricsConfig>(
            MetricsConfig { cardinality_keep_params: vec!["language".to_string()] }
        );
        srv.call(req)
    })
    .route(web::get().to(handler));
```

See the full example `with_cardinality_on_params.rs`.

### Configurable metric names

If you want to rename the default metrics, you can use `ActixMetricsConfiguration` to do so.

```rust
use actix_web_prom::{PrometheusMetricsBuilder, ActixMetricsConfiguration};

PrometheusMetricsBuilder::new("api")
    .endpoint("/metrics")
    .metrics_configuration(
        ActixMetricsConfiguration::default()
        .http_requests_duration_seconds_name("my_http_request_duration"),
    )
    .build()
    .unwrap();
```
See full example `configuring_default_metrics.rs`.
