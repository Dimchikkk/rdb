#[inline(always)]
fn scratch_ears() -> usize {
    1
}

#[inline(always)]
fn pet_cat() -> usize {
    scratch_ears();
    2
}

fn find_happiness() -> usize {
    pet_cat();
    3
}

fn main() {
    let _ = find_happiness();
    let _ = find_happiness();
}
