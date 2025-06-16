fn add(a: i32, b: i32) -> i32 {
    let result = a + b;
    result
}

fn main() {
    // Get a pointer to the function `add`
    let add_ptr: fn(i32, i32) -> i32 = add;
    println!("06-add output: address of add function {:p}", add_ptr as *const ());

    let x = 5;
    let y = 7;
    let sum = add(x, y);
    println!("06-add output: sum is {}", sum);
}
