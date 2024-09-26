pub fn format_size(size: usize) -> String {
    let mut s = String::new();
    if size > 1024 * 1024 {
        s.push_str(&format!("{:.2}", size as f64 / 1024.0 / 1024.0));
        s.push_str("MB");
    } else if size > 1024 {
        s.push_str(&format!("{:.2}", size as f64 / 1024.0));
        s.push_str("KB");
    } else {
        s.push_str(&format!("{}B", size));
    }
    s
}
