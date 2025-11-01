fn add(a: i32, b: i32) -> i32 {
    println!("Adding {} and {}", a, b);
    a + b
}

fn multiply(a: i32, b: i32) -> i32 {
    println!("Multiplying {} and {}", a, b);
    a * b
}

fn calculate(x: i32, y: i32) -> i32 {
    let sum = add(x, y);
    let product = multiply(x, y);
    sum + product
}

fn main() {
    println!("Starting calculation...");
    let result = calculate(3, 4);
    println!("Result: {}", result);
    println!("Done!");
}
