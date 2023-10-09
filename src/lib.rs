/*!
Prometheus instrumentation for [actix-web](https://github.com/actix/actix-web). This middleware is heavily influenced by the work in [sd2k/rocket_prometheus](https://github.com/sd2k/rocket_prometheus). We track the same default metrics and allow for adding user defined metrics.

By default two metrics are tracked (this assumes the namespace `actix_web_prom`):

  - `actix_web_prom_http_requests_total` (labels: endpoint, method, status): the total number
   of HTTP requests handled by the actix HttpServer.

  - `actix_web_prom_http_requests_duration_seconds` (labels: endpoint, method, status): the
   request duration for all HTTP requests handled by the actix HttpServer.


# Usage

First add `actix-web-prom` to your `Cargo.toml`:

```toml
[dependencies]
actix-web-prom = "0.7.0"
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

# if false {
        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?;
# }
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

## Features
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

## Custom metrics

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

# if false {
        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .data(counter.clone())
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?;
# }
    Ok(())
}
```

## Custom `Registry`

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

# if false {
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
# }
    Ok(())
}

```

*/
#![deny(missing_docs)]

use log::warn;
use std::collections::{HashMap, HashSet};
use std::future::{ready, Future, Ready};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use actix_web::{
    body::{BodySize, EitherBody, MessageBody},
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    http::{
        header::{HeaderValue, CONTENT_TYPE},
        Method, StatusCode, Version,
    },
    web::Bytes,
    Error, HttpMessage,
};
use futures_core::ready;
use pin_project_lite::pin_project;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};

use regex::RegexSet;
use strfmt::strfmt;

/// MetricsConfig define middleware and config struct to change the behaviour of the metrics
/// struct to define some particularities
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// list of params where the cardinality matters
    pub cardinality_keep_params: Vec<String>,
}

#[derive(Debug)]
/// Builder to create new PrometheusMetrics struct.HistogramVec
///
/// It allows setting optional parameters like registry, buckets, etc.
pub struct PrometheusMetricsBuilder {
    namespace: String,
    endpoint: Option<String>,
    const_labels: HashMap<String, String>,
    registry: Registry,
    buckets: Vec<f64>,
    exclude: HashSet<String>,
    exclude_regex: RegexSet,
    exclude_status: HashSet<StatusCode>,
    metrics_configuration: ActixMetricsConfiguration,
}

impl PrometheusMetricsBuilder {
    /// Create new PrometheusMetricsBuilder
    ///
    /// namespace example: "actix"
    pub fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.into(),
            endpoint: None,
            const_labels: HashMap::new(),
            registry: Registry::new(),
            buckets: prometheus::DEFAULT_BUCKETS.to_vec(),
            exclude: HashSet::new(),
            exclude_regex: RegexSet::empty(),
            exclude_status: HashSet::new(),
            metrics_configuration: ActixMetricsConfiguration::default(),
        }
    }

    /// Set actix web endpoint
    ///
    /// Example: "/metrics"
    pub fn endpoint(mut self, value: &str) -> Self {
        self.endpoint = Some(value.into());
        self
    }

    /// Set histogram buckets
    pub fn buckets(mut self, value: &[f64]) -> Self {
        self.buckets = value.to_vec();
        self
    }

    /// Set labels to add on every metrics
    pub fn const_labels(mut self, value: HashMap<String, String>) -> Self {
        self.const_labels = value;
        self
    }

    /// Set registry
    ///
    /// By default one is set and is internal to PrometheusMetrics
    pub fn registry(mut self, value: Registry) -> Self {
        self.registry = value;
        self
    }

    /// Ignore and do not record metrics for specified path.
    pub fn exclude<T: Into<String>>(mut self, path: T) -> Self {
        self.exclude.insert(path.into());
        self
    }

    /// Ignore and do not record metrics for paths matching the regex.
    pub fn exclude_regex<T: Into<String>>(mut self, path: T) -> Self {
        let mut patterns = self.exclude_regex.patterns().to_vec();
        patterns.push(path.into());
        self.exclude_regex = RegexSet::new(patterns).unwrap();
        self
    }

    /// Ignore and do not record metrics for paths returning the status code.
    pub fn exclude_status<T: Into<StatusCode>>(mut self, status: T) -> Self {
        self.exclude_status.insert(status.into());
        self
    }

    /// Set metrics configuration
    pub fn metrics_configuration(mut self, value: ActixMetricsConfiguration) -> Self {
        self.metrics_configuration = value;
        self
    }

    /// Instantiate PrometheusMetrics struct
    pub fn build(self) -> Result<PrometheusMetrics, Box<dyn std::error::Error + Send + Sync>> {
        let http_requests_total_opts = Opts::new(
            self.metrics_configuration
                .http_requests_total
                .name
                .to_owned(),
            "Total number of HTTP requests",
        )
        .namespace(&self.namespace)
        .const_labels(self.const_labels.clone());

        let http_requests_total = IntCounterVec::new(
            http_requests_total_opts,
            &self
                .metrics_configuration
                .http_requests_total
                .labels
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>(),
        )?;

        let http_requests_duration_seconds_opts = HistogramOpts::new(
            self.metrics_configuration
                .http_requests_duration_seconds
                .name
                .to_owned(),
            "HTTP request duration in seconds for all requests",
        )
        .namespace(&self.namespace)
        .buckets(self.buckets.to_vec())
        .const_labels(self.const_labels.clone());

        let http_requests_duration_seconds = HistogramVec::new(
            http_requests_duration_seconds_opts,
            &self
                .metrics_configuration
                .http_requests_duration_seconds
                .labels
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>(),
        )?;

        self.registry
            .register(Box::new(http_requests_total.clone()))?;
        self.registry
            .register(Box::new(http_requests_duration_seconds.clone()))?;

        Ok(PrometheusMetrics {
            http_requests_total,
            http_requests_duration_seconds,
            registry: self.registry,
            namespace: self.namespace,
            endpoint: self.endpoint,
            const_labels: self.const_labels,
            exclude: self.exclude,
            exclude_regex: self.exclude_regex,
            exclude_status: self.exclude_status,
            enable_http_version_label: self.enable_http_version_label,
        })
    }
}

#[derive(Debug)]
/// Configuration for a single metric
///
/// Allows configuring name and labels set for the metric
pub struct ActixMetric {
    name: String,
    labels: Vec<String>,
}

impl ActixMetric {
    /// Create a new metric configuration
    pub fn new(name: &str, labels: Vec<&str>) -> ActixMetric {
        ActixMetric {
            name: name.to_string(),
            labels: labels.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug)]
/// Configuration for the collected metrics
///
/// Stores individual metric configuration objects
pub struct ActixMetricsConfiguration {
    http_requests_total: ActixMetric,
    http_requests_duration_seconds: ActixMetric,
}

impl ActixMetricsConfiguration {
    /// Create the default metrics configuration
    fn default() -> ActixMetricsConfiguration {
        ActixMetricsConfiguration {
            http_requests_total: ActixMetric::new(
                "http_requests_total",
                vec!["endpoint", "method", "status"],
            ),
            http_requests_duration_seconds: ActixMetric::new(
                "http_requests_duration_seconds",
                vec!["endpoint", "method", "status"],
            ),
        }
    }

    /// Set configs for http_requests_total metric
    pub fn http_requests_total(mut self, value: ActixMetric) -> Self {
        self.http_requests_total = value;
        self
    }

    /// Set configs for http_requests_duration_seconds metric
    pub fn http_requests_duration_seconds(mut self, value: ActixMetric) -> Self {
        self.http_requests_duration_seconds = value;
        self
    }
}

#[derive(Clone)]
#[must_use = "must be set up as middleware for actix-web"]
/// By default two metrics are tracked (this assumes the namespace `actix_web_prom`):
///
///   - `actix_web_prom_http_requests_total` (labels: endpoint, method, status): the total
///   number of HTTP requests handled by the actix HttpServer.
///
///   - `actix_web_prom_http_requests_duration_seconds` (labels: endpoint, method,
///    status): the request duration for all HTTP requests handled by the actix
///    HttpServer.
pub struct PrometheusMetrics {
    pub(crate) http_requests_total: IntCounterVec,
    pub(crate) http_requests_duration_seconds: HistogramVec,

    /// exposed registry for custom prometheus metrics
    pub registry: Registry,
    #[allow(dead_code)]
    pub(crate) namespace: String,
    pub(crate) endpoint: Option<String>,
    #[allow(dead_code)]
    pub(crate) const_labels: HashMap<String, String>,

    pub(crate) exclude: HashSet<String>,
    pub(crate) exclude_regex: RegexSet,
    pub(crate) exclude_status: HashSet<StatusCode>,
    pub(crate) enable_http_version_label: bool,
}

impl PrometheusMetrics {
    fn metrics(&self) -> String {
        let mut buffer = vec![];
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buffer)
            .unwrap();

        #[cfg(feature = "process")]
        {
            let mut process_metrics = vec![];
            TextEncoder::new()
                .encode(&prometheus::gather(), &mut process_metrics)
                .unwrap();

            buffer.extend_from_slice(&process_metrics);
        }

        String::from_utf8(buffer).unwrap()
    }

    fn matches(&self, path: &str, method: &Method) -> bool {
        if self.endpoint.is_some() {
            self.endpoint.as_ref().unwrap() == path && method == Method::GET
        } else {
            false
        }
    }

    fn update_metrics(
        &self,
        http_version: Version,
        mixed_pattern: &str,
        fallback_pattern: &str,
        method: &Method,
        status: StatusCode,
        clock: Instant,
    ) {
        if self.exclude.contains(mixed_pattern)
            || self.exclude_regex.is_match(mixed_pattern)
            || self.exclude_status.contains(&status)
        {
            return;
        }

        // do not record mixed patterns that were considered invalid by the server
        let final_pattern = if fallback_pattern != mixed_pattern && (status == 404 || status == 405)
        {
            fallback_pattern
        } else {
            mixed_pattern
        };

        let label_values = [
            Self::http_version_label(http_version),
            final_pattern,
            method.as_str(),
            status.as_str(),
        ];
        let label_values = if self.enable_http_version_label {
            &label_values[..]
        } else {
            &label_values[1..]
        };

        let elapsed = clock.elapsed();
        let duration =
            (elapsed.as_secs() as f64) + f64::from(elapsed.subsec_nanos()) / 1_000_000_000_f64;
        self.http_requests_duration_seconds
            .with_label_values(label_values)
            .observe(duration);

        self.http_requests_total
            .with_label_values(label_values)
            .inc();
    }

    fn http_version_label(version: Version) -> &'static str {
        match version {
            v if v == Version::HTTP_09 => "HTTP/0.9",
            v if v == Version::HTTP_10 => "HTTP/1.0",
            v if v == Version::HTTP_11 => "HTTP/1.1",
            v if v == Version::HTTP_2 => "HTTP/2.0",
            v if v == Version::HTTP_3 => "HTTP/3.0",
            _ => "<unrecognized>",
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for PrometheusMetrics
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Response = ServiceResponse<EitherBody<StreamLog<B>, StreamLog<String>>>;
    type Error = Error;
    type InitError = ();
    type Transform = PrometheusMetricsMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PrometheusMetricsMiddleware {
            service,
            inner: Arc::new(self.clone()),
        }))
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct LoggerResponse<S>
        where
        S: Service<ServiceRequest>,
    {
        #[pin]
        fut: S::Future,
        time: Instant,
        inner: Arc<PrometheusMetrics>,
        _t: PhantomData<()>,
    }
}

impl<S, B> Future for LoggerResponse<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Output = Result<ServiceResponse<EitherBody<StreamLog<B>, StreamLog<String>>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let res = match ready!(this.fut.poll(cx)) {
            Ok(res) => res,
            Err(e) => return Poll::Ready(Err(e)),
        };

        let time = *this.time;
        let req = res.request();
        let method = req.method().clone();
        let version = req.version();

        // get metrics config for this specific route
        // piece of code to allow for more cardinality
        let params_keep_path_cardinality = match req.extensions_mut().get::<MetricsConfig>() {
            Some(config) => config.cardinality_keep_params.clone(),
            None => vec![],
        };

        let full_pattern = req.match_pattern();
        let path = req.path().to_string();
        let fallback_pattern = full_pattern.clone().unwrap_or(path.clone());

        // mixed_pattern is the final path used as label value in metrics
        let mixed_pattern = match full_pattern {
            None => path.clone(),
            Some(full_pattern) => {
                let mut params: HashMap<String, String> = HashMap::new();

                for (key, val) in req.match_info().iter() {
                    if params_keep_path_cardinality.contains(&key.to_string()) {
                        params.insert(key.to_string(), val.to_string());
                        continue;
                    }
                    params.insert(key.to_string(), format!("{{{}}}", key));
                }

                match strfmt(&full_pattern, &params) {
                    Ok(mixed_cardinality_pattern) => mixed_cardinality_pattern,
                    Err(_) => {
                        warn!("Cannot build mixed cardinality pattern {:?}", full_pattern);
                        full_pattern
                    }
                }
            }
        };

        let inner = this.inner.clone();

        Poll::Ready(Ok(res.map_body(move |head, body| {
            // We short circuit the response status and body to serve the endpoint
            // automagically. This way the user does not need to set the middleware *AND*
            // an endpoint to serve middleware results. The user is only required to set
            // the middleware and tell us what the endpoint should be.
            if inner.matches(&path, &method) {
                head.status = StatusCode::OK;
                head.headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                );

                EitherBody::right(StreamLog {
                    body: inner.metrics(),
                    size: 0,
                    clock: time,
                    inner,
                    status: head.status,
                    mixed_pattern,
                    fallback_pattern,
                    method,
                    version,
                })
            } else {
                EitherBody::left(StreamLog {
                    body,
                    size: 0,
                    clock: time,
                    inner,
                    status: head.status,
                    mixed_pattern,
                    fallback_pattern,
                    method,
                    version,
                })
            }
        })))
    }
}

#[doc(hidden)]
/// Middleware service for PrometheusMetrics
pub struct PrometheusMetricsMiddleware<S> {
    service: S,
    inner: Arc<PrometheusMetrics>,
}

impl<S, B> Service<ServiceRequest> for PrometheusMetricsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Response = ServiceResponse<EitherBody<StreamLog<B>, StreamLog<String>>>;
    type Error = S::Error;
    type Future = LoggerResponse<S>;

    dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        LoggerResponse {
            fut: self.service.call(req),
            time: Instant::now(),
            inner: self.inner.clone(),
            _t: PhantomData,
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct StreamLog<B> {
        #[pin]
        body: B,
        size: usize,
        clock: Instant,
        inner: Arc<PrometheusMetrics>,
        status: StatusCode,
        // a route pattern with some params not-filled and some params filled in by user-defined
        mixed_pattern: String,
        fallback_pattern: String,
        method: Method,
        version: Version,
    }


    impl<B> PinnedDrop for StreamLog<B> {
        fn drop(this: Pin<&mut Self>) {
            // update the metrics for this request at the very end of responding
            this.inner
                .update_metrics(this.version, &this.mixed_pattern, &this.fallback_pattern, &this.method, this.status, this.clock);
        }
    }
}

impl<B: MessageBody> MessageBody for StreamLog<B> {
    type Error = B::Error;

    fn size(&self) -> BodySize {
        self.body.size()
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        let this = self.project();
        match ready!(this.body.poll_next(cx)) {
            Some(Ok(chunk)) => {
                *this.size += chunk.len();
                Poll::Ready(Some(Ok(chunk)))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            None => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::dev::Service;
    use actix_web::test::{call_and_read_body, call_service, init_service, read_body, TestRequest};
    use actix_web::{web, App, HttpMessage, HttpResponse, Resource, Scope};

    use prometheus::{Counter, Opts};

    #[actix_web::test]
    async fn middleware_basic() {
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(&app, TestRequest::with_uri("/health_check").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_service(&app, TestRequest::with_uri("/metrics").to_request()).await;
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = String::from_utf8(read_body(res).await.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE actix_web_prom_http_requests_duration_seconds histogram
actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/health_check\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/health_check\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_web::test]
    async fn middleware_http_version() {
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .enable_http_version_label(true)
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        let test_cases = HashMap::from([
            (Version::HTTP_09, 1),
            (Version::HTTP_10, 2),
            (Version::HTTP_11, 5),
            (Version::HTTP_2, 7),
            (Version::HTTP_3, 11),
        ]);

        for (http_version, repeats) in test_cases.iter() {
            for _ in 0..*repeats {
                let res = call_service(
                    &app,
                    TestRequest::with_uri("/health_check")
                        .version(*http_version)
                        .to_request(),
                )
                .await;
                assert!(res.status().is_success());
                assert_eq!(read_body(res).await, "");
            }
        }

        let res = call_service(&app, TestRequest::with_uri("/metrics").to_request()).await;
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = String::from_utf8(read_body(res).await.to_vec()).unwrap();
        println!("Body: {}", body);
        for (http_version, repeats) in test_cases {
            assert!(&body.contains(
                &String::from_utf8(web::Bytes::from(
                    format!(
                        "actix_web_prom_http_requests_duration_seconds_bucket{{endpoint=\"/health_check\",method=\"GET\",status=\"200\",version=\"{}\",le=\"0.005\"}} {}
", PrometheusMetrics::http_version_label(http_version), repeats)
            ).to_vec()).unwrap()));

            assert!(&body.contains(
                &String::from_utf8(web::Bytes::from(
                    format!(
                        "actix_web_prom_http_requests_total{{endpoint=\"/health_check\",method=\"GET\",status=\"200\",version=\"{}\"}} {}
", PrometheusMetrics::http_version_label(http_version), repeats)
            ).to_vec()).unwrap()));
        }
    }

    #[actix_web::test]
    async fn middleware_scope() {
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/internal/metrics")
            .build()
            .unwrap();

        let app = init_service(
            App::new().service(
                web::scope("/internal")
                    .wrap(prometheus)
                    .service(web::resource("/health_check").to(HttpResponse::Ok)),
            ),
        )
        .await;

        let res = call_service(
            &app,
            TestRequest::with_uri("/internal/health_check").to_request(),
        )
        .await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_service(
            &app,
            TestRequest::with_uri("/internal/metrics").to_request(),
        )
        .await;
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = String::from_utf8(read_body(res).await.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE actix_web_prom_http_requests_duration_seconds histogram
actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/internal/health_check\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/internal/health_check\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_web::test]
    async fn middleware_match_pattern() {
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/resource/{id}").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(&app, TestRequest::with_uri("/resource/123").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE actix_web_prom_http_requests_duration_seconds histogram
actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/resource/{id}\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/resource/{id}\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_web::test]
    async fn middleware_with_mixed_params_cardinality() {
        // we want to keep metrics label on the "cheap param" but not on the "expensive" param
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .build()
            .unwrap();

        let app = init_service(
            App::new().wrap(prometheus).service(
                web::resource("/resource/{cheap}/{expensive}")
                    .wrap_fn(|req, srv| {
                        req.extensions_mut().insert::<MetricsConfig>(MetricsConfig {
                            cardinality_keep_params: vec!["cheap".to_string()],
                        });
                        srv.call(req)
                    })
                    .to(|path: web::Path<(String, String)>| async {
                        let (cheap, _expensive) = path.into_inner();
                        if !["foo", "bar"].map(|x| x.to_string()).contains(&cheap) {
                            return HttpResponse::NotFound().finish();
                        }
                        HttpResponse::Ok().finish()
                    }),
            ),
        )
        .await;

        // first probe to check basic facts
        let res = call_service(
            &app,
            TestRequest::with_uri("/resource/foo/12345").to_request(),
        )
        .await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        println!("Body: {}", body);
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/resource/foo/{expensive}\",method=\"GET\",status=\"200\",le=\"0.005\"} 1"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "actix_web_prom_http_requests_total{endpoint=\"/resource/foo/{expensive}\",method=\"GET\",status=\"200\"} 1"
                )
                .to_vec()
            )
            .unwrap()
        ));

        // second probe to test 404 behavior
        let res = call_service(
            &app,
            TestRequest::with_uri("/resource/invalid/92945").to_request(),
        )
        .await;
        assert!(res.status() == 404);
        assert_eq!(read_body(res).await, "");

        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        println!("Body: {}", body);
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "actix_web_prom_http_requests_total{endpoint=\"/resource/{cheap}/{expensive}\",method=\"GET\",status=\"404\"} 1"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_web::test]
    async fn middleware_metrics_exposed_with_conflicting_pattern() {
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/{path}").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(&app, TestRequest::with_uri("/something").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests"
        ).to_vec()).unwrap()));
    }

    #[actix_web::test]
    async fn middleware_basic_failure() {
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/prometheus")
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        call_service(&app, TestRequest::with_uri("/health_checkz").to_request()).await;
        let res = call_and_read_body(&app, TestRequest::with_uri("/prometheus").to_request()).await;
        assert!(String::from_utf8(res.to_vec()).unwrap().contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/health_checkz\",method=\"GET\",status=\"404\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_web::test]
    async fn middleware_custom_counter() {
        let counter_opts = Opts::new("counter", "some random counter").namespace("actix_web_prom");
        let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();

        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .build()
            .unwrap();

        prometheus
            .registry
            .register(Box::new(counter.clone()))
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        // Verify that 'counter' does not appear in the output before we use it
        call_service(&app, TestRequest::with_uri("/health_check").to_request()).await;
        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        assert!(!String::from_utf8(res.to_vec()).unwrap().contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_counter some random counter
# TYPE actix_web_prom_counter counter
actix_web_prom_counter{endpoint=\"endpoint\",method=\"method\",status=\"status\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));

        // Verify that 'counter' appears after we use it
        counter
            .with_label_values(&["endpoint", "method", "status"])
            .inc();
        counter
            .with_label_values(&["endpoint", "method", "status"])
            .inc();
        call_service(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        assert!(String::from_utf8(res.to_vec()).unwrap().contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_counter some random counter
# TYPE actix_web_prom_counter counter
actix_web_prom_counter{endpoint=\"endpoint\",method=\"method\",status=\"status\"} 2
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_web::test]
    async fn middleware_none_endpoint() {
        // Init PrometheusMetrics with none URL
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .build()
            .unwrap();

        let app = init_service(App::new().wrap(prometheus.clone()).service(
            web::resource("/metrics").to(|| async { HttpResponse::Ok().body("not prometheus") }),
        ))
        .await;

        let response =
            call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;

        // Assert app works
        assert_eq!(
            String::from_utf8(response.to_vec()).unwrap(),
            "not prometheus"
        );

        // Assert counter counts
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = prometheus.registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();

        assert!(output.contains(
            "actix_web_prom_http_requests_total{endpoint=\"/metrics\",method=\"GET\",status=\"200\"} 1"
        ));
    }

    #[actix_web::test]
    async fn middleware_custom_registry_works() {
        // Init Prometheus Registry
        let registry = Registry::new();

        let counter_opts = Opts::new("test_counter", "test counter help");
        let counter = Counter::with_opts(counter_opts).unwrap();
        registry.register(Box::new(counter.clone())).unwrap();

        counter.inc_by(10_f64);

        // Init PrometheusMetrics
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .registry(registry)
            .endpoint("/metrics")
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus.clone())
                .service(web::resource("/test").to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        // all http counters are 0 because this is the first http request,
        // so we should get only 10 on test counter
        let response =
            call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(response.to_vec()).unwrap();

        let ten_test_counter =
            "# HELP test_counter test counter help\n# TYPE test_counter counter\ntest_counter 10\n";
        assert!(body.contains(ten_test_counter));

        // all http counters are 1 because this is the second http request,
        // plus 10 on test counter
        let response =
            call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let response_string = String::from_utf8(response.to_vec()).unwrap();

        let one_http_counters = "# HELP actix_web_prom_http_requests_total Total number of HTTP requests\n# TYPE actix_web_prom_http_requests_total counter\nactix_web_prom_http_requests_total{endpoint=\"/metrics\",method=\"GET\",status=\"200\"} 1";

        assert!(response_string.contains(ten_test_counter));
        assert!(response_string.contains(one_http_counters));
    }

    #[actix_web::test]
    async fn middleware_const_labels() {
        let mut labels = HashMap::new();
        labels.insert("label1".to_string(), "value1".to_string());
        labels.insert("label2".to_string(), "value2".to_string());
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .const_labels(labels)
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(&app, TestRequest::with_uri("/health_check").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE actix_web_prom_http_requests_duration_seconds histogram
actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/health_check\",label1=\"value1\",label2=\"value2\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/health_check\",label1=\"value1\",label2=\"value2\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_web::test]
    async fn middleware_metrics_configuration() {
        let metrics_config = ActixMetricsConfiguration::default()
            .http_requests_duration_seconds(ActixMetric::new("my_http_request_duration", vec!["path", "method", "status"]))
            .http_requests_total(ActixMetric::new("my_http_requests_total", vec!["path", "method", "status"]));

        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .metrics_configuration(metrics_config)
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(&app, TestRequest::with_uri("/health_check").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_and_read_body(&app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_my_http_request_duration HTTP request duration in seconds for all requests
# TYPE actix_web_prom_my_http_request_duration histogram
actix_web_prom_my_http_request_duration_bucket{method=\"GET\",path=\"/health_check\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_my_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_my_http_requests_total counter
actix_web_prom_my_http_requests_total{method=\"GET\",path=\"/health_check\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[test]
    fn compat_with_non_boxed_middleware() {
        let _app = App::new()
            .wrap(PrometheusMetricsBuilder::new("").build().unwrap())
            .wrap(actix_web::middleware::Logger::default())
            .route("", web::to(|| async { "" }));

        let _app = App::new()
            .wrap(actix_web::middleware::Logger::default())
            .wrap(PrometheusMetricsBuilder::new("").build().unwrap())
            .route("", web::to(|| async { "" }));

        let _scope = Scope::new("")
            .wrap(PrometheusMetricsBuilder::new("").build().unwrap())
            .route("", web::to(|| async { "" }));

        let _resource = Resource::new("")
            .wrap(PrometheusMetricsBuilder::new("").build().unwrap())
            .route(web::to(|| async { "" }));
    }

    #[actix_web::test]
    async fn middleware_excludes() {
        let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
            .endpoint("/metrics")
            .exclude("/ping")
            .exclude_regex("/readyz/.*")
            .exclude_status(StatusCode::NOT_FOUND)
            .build()
            .unwrap();

        let app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok))
                .service(web::resource("/ping").to(HttpResponse::Ok))
                .service(web::resource("/readyz/{subsystem}").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(&app, TestRequest::with_uri("/health_check").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_service(&app, TestRequest::with_uri("/ping").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_service(&app, TestRequest::with_uri("/readyz/database").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_service(&app, TestRequest::with_uri("/notfound").to_request()).await;
        assert!(res.status().is_client_error());
        assert_eq!(read_body(res).await, "");

        let res = call_service(&app, TestRequest::with_uri("/metrics").to_request()).await;
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = String::from_utf8(read_body(res).await.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/health_check\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));

        assert!(!&body.contains("endpoint=\"/ping\""));
        assert!(!&body.contains("endpoint=\"/readyz"));
        assert!(!body.contains("endpoint=\"/notfound"));
    }
}
