use fourq::point::Point;
use fourq::scalar::Scalar;
use std::hint::black_box;
use std::time::Instant;

fn random_scalar() -> Scalar {
    Scalar::new(rand::random::<[u8; 32]>())
}

fn main() {
    let s = random_scalar();

    let points: Vec<Point> = (0..1_000_000)
        .map(|_| {
            let r = random_scalar();
            let bytes: [u8; 32] = r.into();
            Point::from_hash(&bytes)
        })
        .collect();

    let started = Instant::now();
    let products: Vec<Point> = points.iter().map(|p| *p * s).collect();
    let elapsed = started.elapsed();

    black_box(products);
    println!("computed {} multiplications in {:?}", points.len(), elapsed);
}
