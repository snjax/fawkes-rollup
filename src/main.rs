pub mod circuit;



fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        if args[1] == "setup" {
            crate::circuit::bench::rollup_bencher_setup();
        } else if args[1] == "proof" {
            crate::circuit::bench::rollup_bencher_proof();
        } else if args[1] == "info" {
            crate::circuit::bench::rollup_bencher_info();
        }
    }
    
}
