extern crate rabe;
#[macro_use]
extern crate criterion;

use criterion::{criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use rabe::schemes;


fn criterion_compare_schemes_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup");
    group.bench_with_input(BenchmarkId::new("AC17", 1), &1_usize, |b, &_usize| {
        b.iter(|| {
            schemes::ac17::setup()
        } );
    });
    group.bench_with_input(BenchmarkId::new("AW11", 1), &1_usize, |b, &_usize| {
        b.iter(|| {
            schemes::aw11::setup()
        } );
    });
    group.bench_with_input(BenchmarkId::new("BDABE", 1), &1_usize, |b, &_usize| {
        b.iter(|| {
            schemes::bdabe::setup()
        } );
    });
    group.bench_with_input(BenchmarkId::new("BSW", 1), &1_usize, |b, &_usize| {
        b.iter(|| {
            schemes::bsw::setup()
        } );
    });
    group.bench_with_input(BenchmarkId::new("LSW", 1), &1_usize, |b, &_usize| {
        b.iter(|| {
            schemes::lsw::setup()
        } );
    });
    group.bench_with_input(BenchmarkId::new("MKE08", 1), &1_usize, |b, &_usize| {
        b.iter(|| {
            schemes::mke08::setup()
        } );
    });
    group.bench_with_input(BenchmarkId::new("YCT14", 1), &1_usize, |b, &_usize| {
        b.iter(|| {
            schemes::yct14::setup((0..10).into_iter().map(|v: usize| v.to_string()).collect())
        } );
    });
    group.finish();
}

criterion_group!(benches,
    criterion_compare_schemes_setup,
);

criterion_main!(benches);