fn main() {
    let v: smallvec::SmallVec<[u8; 4]> = smallvec::SmallVec::new();
    println!("{}", v.len());
}
