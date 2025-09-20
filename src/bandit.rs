// Minimal LinUCB for small feature spaces (d <= 8)
pub struct LinUcb {
    d: usize,
    alpha: f64,
    a: Vec<Vec<Vec<f64>>>, // per-arm A (d x d)
    b: Vec<Vec<f64>>,      // per-arm b (d)
}

impl LinUcb {
    pub fn new(num_arms: usize, d: usize, alpha: f64) -> Self {
        let mut a = Vec::with_capacity(num_arms);
        let mut b = Vec::with_capacity(num_arms);
        for _ in 0..num_arms {
            let mut m = vec![vec![0.0; d]; d];
            for i in 0..d { m[i][i] = 1.0; } // ridge I
            a.push(m);
            b.push(vec![0.0; d]);
        }
        Self { d, alpha, a, b }
    }

    fn invert(m: &Vec<Vec<f64>>) -> Vec<Vec<f64>> {
        let n = m.len();
        let mut a = vec![vec![0.0; 2*n]; n];
        for i in 0..n {
            for j in 0..n { a[i][j] = m[i][j]; }
            a[i][n+i] = 1.0;
        }
        for i in 0..n {
            // pivot
            let mut piv = i;
            let mut maxv = a[i][i].abs();
            for r in (i+1)..n {
                if a[r][i].abs() > maxv { maxv = a[r][i].abs(); piv = r; }
            }
            if piv != i { a.swap(i, piv); }
            let div = a[i][i];
            if div.abs() < 1e-12 { continue; }
            for c in 0..2*n { a[i][c] /= div; }
            // eliminate
            for r in 0..n {
                if r == i { continue; }
                let f = a[r][i];
                if f.abs() < 1e-18 { continue; }
                for c in 0..2*n { a[r][c] -= f * a[i][c]; }
            }
        }
        let mut inv = vec![vec![0.0; n]; n];
        for i in 0..n {
            for j in 0..n { inv[i][j] = a[i][n+j]; }
        }
        inv
    }

    fn mat_vec(m: &Vec<Vec<f64>>, x: &Vec<f64>) -> Vec<f64> {
        let n = m.len();
        let mut out = vec![0.0; n];
        for i in 0..n {
            let mut s = 0.0;
            for j in 0..n { s += m[i][j] * x[j]; }
            out[i] = s;
        }
        out
    }

    fn dot(a: &Vec<f64>, b: &Vec<f64>) -> f64 {
        a.iter().zip(b.iter()).map(|(x,y)| x*y).sum()
    }

    pub fn select(&self, x: &Vec<f64>, allowed: Option<&[usize]>) -> usize {
        let candidates: Vec<usize> = match allowed {
            Some(ids) => ids.to_vec(),
            None => (0..self.a.len()).collect(),
        };
        let mut best_i = *candidates.first().unwrap_or(&0);
        let mut best_p = f64::NEG_INFINITY;
        for &i in &candidates {
            let a_inv = Self::invert(&self.a[i]);
            let theta = Self::mat_vec(&a_inv, &self.b[i]);
            let est = Self::dot(&theta, x);
            let tmp = Self::mat_vec(&a_inv, x);
            let mut xax = 0.0;
            for j in 0..self.d { xax += x[j] * tmp[j]; }
            let p = est + self.alpha * xax.max(0.0).sqrt();
            if p > best_p { best_p = p; best_i = i; }
        }
        best_i
    }

    pub fn update(&mut self, arm: usize, x: &Vec<f64>, reward: f64) {
        for i in 0..self.d {
            for j in 0..self.d {
                self.a[arm][i][j] += x[i] * x[j];
            }
        }
        for i in 0..self.d {
            self.b[arm][i] += reward * x[i];
        }
    }
}