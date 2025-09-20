// src/topology.rs
pub fn to_cpuset_list(cpus: &[usize]) -> String {
    let mut v = cpus.to_vec();
    v.sort_unstable(); v.dedup();
    let mut out = String::new();
    let mut i = 0;
    while i < v.len() {
        let s = v[i];
        let mut j = i;
        while j+1 < v.len() && v[j+1] == v[j]+1 { j+=1; }
        if !out.is_empty() { out.push(','); }
        if j == i { out.push_str(&format!("{}", s)); }
        else { out.push_str(&format!("{}-{}", s, v[j])); }
        i = j+1;
    }
    out
}