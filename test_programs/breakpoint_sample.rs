use std::hint::black_box;

#[no_mangle]
pub extern "C" fn print_type_i32(_: i32) {
    black_box(42_i32);
}

#[no_mangle]
pub extern "C" fn print_type_f64(_: f64) {
    black_box(3.14_f64);
}

#[no_mangle]
pub extern "C" fn print_type_str() {
    black_box(());
}

fn main() {
    print_type_i32(0);
    print_type_str();
    print_type_f64(0.0);
    print_type_str();
}
